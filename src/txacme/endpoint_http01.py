import attr
from attr.validators import optional, provides, instance_of
from twisted.python.filepath import IFilePath
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.internet.interfaces import IStreamServerEndpoint
from twisted.internet.endpoints import serverFromString
from josepy.jwa import RS256
from txsni.snimap import HostDirectoryMap, SNIMap
from txsni.maputils import Cache
from txsni.tlsendpoint import TLSEndpoint
from txacme.service import AcmeIssuingService
from txacme.client import Client
from txacme.store import DirectoryStore
from txacme.challenges import HTTP01Responder
from txacme.util import check_directory_url_type
from .endpoint import load_or_create_client_key

class _WrappedListeningPort(object):
    _tlsListeningPort = attr.ib()
    _acmeService = attr.ib()
    _responderListeningPort = attr.ib()

    @inlineCallbacks
    def stopListening(self):
        yield self._tlsListeningPort.stopListening()
        yield self._acmeService.stopService()
        yield self._responderListeningPort.stopListening()
        # fires with None

@attr.s
class AcmeHTTP01Endpoint(object):
    _reactor = attr.ib()
    _directory = attr.ib(
        validator=lambda inst, a, value: check_directory_url_type(value))
    _certPath = attr.ib(validator=provides(IFilePath))
    _tlsEndpoint = attr.ib(validator=optional(IStreamServerEndpoint))
    _responderEndpoint = attr.ib(validator=optional(IStreamServerEndpoint))
    _forwardHTTP = attr.ib(validator=instance_of(bool), default=True)

    @inlineCallbacks
    def listen(self, protocolFactory):
        reactor = self._reactor
        certPath = self._certPath.asTextMode()
        tlsEndpoint = (serverFromString(reactor, "tcp:443")
                       if self._tlsEndpoint is None
                       else self._tlsEndpoint)
        responderEndpoint = (serverFromString(reactor, "tcp:80")
                             if self._responderEndpoint is None
                             else self._responderEndpoint)

        # we have responders for tls-sni-01
        # staging ACME server offers http-01 and dns-01
        # so we need to use an HTTP01Responder
        cert_store = DirectoryStore(certPath)
        acme_key = load_or_create_client_key(certPath)
        def client_creator():
            return Client.from_url(reactor, self._directory,
                                   key=acme_key, alg=RS256)
        acmeresp = HTTP01Responder()
        acmeserv = AcmeIssuingService(cert_store, client_creator, reactor,
                                      responders=[acmeresp])

        root = Resource()
        well_known = Resource()
        well_known.putChild(b"acme-challenge", acmeresp.resource)
        root.putChild(b".well-known", well_known)
        if self._forwardHTTP:
            pass # TODO: add per-url redirect
        responder_site = Site(root)

        # Start the HTTP server and make sure it's running before we start the
        # issuing service, so we'll be prepared for server challenges in time.

        responder_lp = yield responderEndpoint.listen(responder_site)
        # we need the lp to shut it down again later

        # start requesting certificates from the ACME server, which will send
        # challenges to our HTTP responder
        acmeserv.startService()

        # wait until initial issuing is complete: we have updated certificates
        # and private keys for all hostnames in the certPath directory
        yield acmeserv.when_certs_valid()

        # now we can build the TLSEndpoint around the user-supplied listening
        # endpoint

        # This is copied from txsni/parser.py, which is unfortunately not
        # exposed as a single function we could invoke
        contextFactory = SNIMap(Cache(HostDirectoryMap(certPath)))
        wrapped_ep = TLSEndpoint(endpoint=tlsEndpoint,
                                 contextFactory=contextFactory)

        # start the user-supplied endpoint, and grab its ListeningPort so we
        # intercept the call to its .stopListening and shut everything else
        # down too
        tls_lp = yield wrapped_ep.listen(protocolFactory)

        # the caller gets this wrapper
        wrapped_lp = _WrappedListeningPort(tls_lp, acmeserv, responder_lp)
        returnValue(wrapped_lp)


# we've got four Endpoint-like objects and a Service
# * exposed endpoint: the AcmeHTTP01Endpoint instance callers get back
# * responder EP: provided by caller or defaults to tcp:80
# * TLS EP: provided by caller or defaults to tcp:443
# * TLSWrapper EP: provides contextFactory, wraps caller-provided TLS EP
#   (this is a just a txsni.tlsendpoint.TLSEndpoint)
# * AcmeIssuingService

# when the exposed endpoint's .listen is called, we must:
# * responderEP.listen, wait for the ListeningPort to be ready, stash it
# * now it's safe to send ACME requests, as our responder is ready to answer
# * then AcmeIssuingService.startService()
# * then wait for issuer.when_certs_valid(), to make sure all desired
#   certificates are ready
# * then call TLSWrapper.listen, wait for its ListeningPort, stash it
# * then build a new WrapperListeningPort instance
# * finally fire the return Deferred with that new instance

# Later, when the app calls .stopListening on the WrapperListeningPort we gave
# them, we must unwind everything:
# * call .stopListening on the LP we got from TLSWrapper.listen
#   (this LP will have come from the caller-supplied TLS EP)
# * when that fires, we know we'll no longer get any TLS requests, so it's
#   safe to shut down the ACME service (although to be honest we could shut
#   it down earlier, since we still have the certs)
# * then stopService the ACME service, wait for its maybeDeferred to fire
# * then use the stashed LP from responderEP.listen to .stopListening
# * wait for *its* Deferred to fire
# * finally fire the return Deferred
