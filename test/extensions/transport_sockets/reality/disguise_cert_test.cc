#include <algorithm>
#include <cstring>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "envoy/extensions/transport_sockets/reality/v3/reality.pb.h"

#include "source/extensions/transport_sockets/reality/reality_config.h"
#include "source/extensions/transport_sockets/reality/reality_handshaker.h"

#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {
namespace {

// Mirrors the constants realityDisguiseCertTargetDerLen() is derived from. They
// are verified end to end by DisguiseCertMatchesMirrorFlight below, which runs a
// real TLS 1.3 handshake and measures the emitted messages.
constexpr size_t kCertificateMsgOverhead = 13;
constexpr size_t kEd25519CertificateVerifyMsgLen = 72;

envoy::extensions::transport_sockets::reality::v3::RealityConfig minimalProto() {
  envoy::extensions::transport_sockets::reality::v3::RealityConfig proto;
  // 32 zero bytes, base64url. The X25519 key is irrelevant here; only the
  // Ed25519 disguise-leaf machinery is under test.
  proto.set_private_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  proto.set_short_id("0123456789abcdef");
  proto.set_mirror_target("example.com:443");
  return proto;
}

class DisguiseCertTest : public testing::Test {
protected:
  DisguiseCertTest() : api_(Api::createApiForTest()), config_(minimalProto(), *api_) {}

  Api::ApiPtr api_;
  RealityConfig config_;
};

// The target length folds the mirror's CertificateVerify size into the
// certificate, because our Ed25519 CertificateVerify is a fixed 72 bytes while
// the mirror signs with RSA-PSS or ECDSA.
TEST(DisguiseCertTargetTest, FoldsCertificateVerifyIntoCertificate) {
  // RSA-2048: Certificate 2890, CertificateVerify 264 -> flight 3154.
  EXPECT_EQ(3154 - kCertificateMsgOverhead - kEd25519CertificateVerifyMsgLen,
            realityDisguiseCertTargetDerLen(2890, 264));
  // ECDSA P-256: the mirror's CertificateVerify is close to ours, so the target
  // is close to the mirror's certificate DER size.
  EXPECT_EQ(1620 + 78 - kCertificateMsgOverhead - kEd25519CertificateVerifyMsgLen,
            realityDisguiseCertTargetDerLen(1620, 78));
}

// Degenerate measurements must disable padding rather than produce a nonsense
// target, so the handshaker falls back to the unpadded certificate.
TEST(DisguiseCertTargetTest, RejectsUnusableMeasurements) {
  EXPECT_EQ(0u, realityDisguiseCertTargetDerLen(0, 0));
  EXPECT_EQ(0u, realityDisguiseCertTargetDerLen(2890, 0));
  EXPECT_EQ(0u, realityDisguiseCertTargetDerLen(kCertificateMsgOverhead, 264));
  EXPECT_EQ(0u, realityDisguiseCertTargetDerLen(20, 20));
}

TEST_F(DisguiseCertTest, RejectsOutOfRangeTargets) {
  // Below the unpadded certificate: nothing to do.
  EXPECT_TRUE(config_.buildDisguiseCert(config_.staticCert().size()).empty());
  EXPECT_TRUE(config_.buildDisguiseCert(1).empty());
  // Above the cap: refuse rather than let a hostile mirror measurement drive an
  // unbounded allocation.
  EXPECT_TRUE(config_.buildDisguiseCert(RealityConfig::kMaxDisguiseCertDerLen + 1).empty());
}

// The padded leaf must hit the requested DER length, stay a parseable
// certificate, and keep its Ed25519 signature as the trailing 64 bytes — the
// handshaker overwrites exactly those bytes with the REALITY HMAC.
TEST_F(DisguiseCertTest, HitsTargetLengthAndKeepsSignatureTail) {
  size_t exact = 0;
  size_t total = 0;
  size_t worst = 0;
  for (const size_t target : {600u, 1024u, 1613u, 2048u, 3069u, 5535u, 12642u, 30000u}) {
    const std::vector<uint8_t> der = config_.buildDisguiseCert(target);
    ASSERT_FALSE(der.empty()) << "target " << target;
    total++;
    const size_t delta = der.size() > target ? der.size() - target : target - der.size();
    if (delta == 0) {
      exact++;
    }
    worst = std::max(worst, delta);

    const uint8_t* p = der.data();
    bssl::UniquePtr<X509> parsed(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
    ASSERT_NE(nullptr, parsed) << "padded cert of " << der.size() << " bytes does not parse";
    const ASN1_BIT_STRING* sig = nullptr;
    const X509_ALGOR* alg = nullptr;
    X509_get0_signature(&sig, &alg, parsed.get());
    ASSERT_NE(nullptr, sig);
    ASSERT_EQ(64, sig->length);
    EXPECT_EQ(0, memcmp(sig->data, der.data() + der.size() - 64, 64));
  }
  // A few DER lengths are unreachable for every serial width, because the outer
  // length prefixes widen together; those degrade to a 1-byte residual.
  EXPECT_LE(worst, 1u);
  EXPECT_EQ(total, exact) << "worst residual " << worst << " byte(s)";
}

struct FlightSizes {
  size_t encrypted_extensions = 0;
  size_t certificate = 0;
  size_t certificate_verify = 0;
  size_t finished = 0;
};

void recordFlight(int write_p, int, int content_type, const void* buf, size_t len, SSL* ssl, void*) {
  if (write_p != 0 || content_type != SSL3_RT_HANDSHAKE || len < 1) {
    return;
  }
  auto* sizes = static_cast<FlightSizes*>(SSL_get_app_data(ssl));
  if (sizes == nullptr) {
    return;
  }
  switch (static_cast<const uint8_t*>(buf)[0]) {
  case SSL3_MT_ENCRYPTED_EXTENSIONS:
    sizes->encrypted_extensions = len;
    break;
  case SSL3_MT_CERTIFICATE:
    sizes->certificate = len;
    break;
  case SSL3_MT_CERTIFICATE_VERIFY:
    sizes->certificate_verify = len;
    break;
  case SSL3_MT_FINISHED:
    sizes->finished = len;
    break;
  default:
    break;
  }
}

// Runs an in-memory TLS 1.3 handshake with `cert_der` as the server leaf and
// returns the handshake message sizes the client observed.
bool handshakeWithLeaf(EVP_PKEY* key, const std::vector<uint8_t>& cert_der, FlightSizes* sizes) {
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  for (SSL_CTX* ctx : {server_ctx.get(), client_ctx.get()}) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  }
  bssl::UniquePtr<SSL> server(SSL_new(server_ctx.get()));
  bssl::UniquePtr<SSL> client(SSL_new(client_ctx.get()));

  static const uint16_t kEd25519[] = {SSL_SIGN_ED25519};
  if (SSL_use_certificate_ASN1(server.get(), cert_der.data(), cert_der.size()) != 1 ||
      SSL_use_PrivateKey(server.get(), key) != 1 ||
      SSL_set_signing_algorithm_prefs(server.get(), kEd25519, 1) != 1 ||
      // The REALITY client omits Ed25519 and relies on the BoringSSL carve-out;
      // this test client advertises it so the test does not depend on the patch.
      SSL_set_verify_algorithm_prefs(client.get(), kEd25519, 1) != 1) {
    return false;
  }
  SSL_set_verify(client.get(), SSL_VERIFY_NONE, nullptr);
  SSL_set_app_data(client.get(), sizes);
  SSL_set_msg_callback(client.get(), recordFlight);
  SSL_set_tlsext_host_name(client.get(), "reality.test");

  SSL_set_bio(client.get(), BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
  SSL_set_bio(server.get(), BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
  SSL_set_connect_state(client.get());
  SSL_set_accept_state(server.get());

  auto pump = [](BIO* from, BIO* to) {
    char buf[16384];
    int n;
    while ((n = BIO_read(from, buf, sizeof(buf))) > 0) {
      BIO_write(to, buf, n);
    }
  };
  for (int i = 0; i < 32; i++) {
    SSL_do_handshake(client.get());
    pump(SSL_get_wbio(client.get()), SSL_get_rbio(server.get()));
    SSL_do_handshake(server.get());
    pump(SSL_get_wbio(server.get()), SSL_get_rbio(client.get()));
    if (SSL_is_init_finished(client.get()) && SSL_is_init_finished(server.get())) {
      return true;
    }
  }
  return false;
}

// The point of the whole exercise: with a mirror measurement in hand, the
// emitted Certificate + CertificateVerify must be the same size as the mirror
// target's, so an observer of an authenticated session cannot separate the two by
// flight size. Without padding the emitted flight is ~260 bytes regardless of
// what the mirror serves.
TEST_F(DisguiseCertTest, DisguiseCertMatchesMirrorFlight) {
  // Baseline: confirm the two constants the target computation relies on.
  {
    FlightSizes sizes;
    ASSERT_TRUE(handshakeWithLeaf(config_.ed25519PrivateKey(), config_.staticCert(), &sizes));
    EXPECT_EQ(config_.staticCert().size() + kCertificateMsgOverhead, sizes.certificate);
    EXPECT_EQ(kEd25519CertificateVerifyMsgLen, sizes.certificate_verify);
  }

  struct Case {
    const char* name;
    uint32_t certificate_len;
    uint32_t certificate_verify_len;
  };
  const Case cases[] = {
      {"ECDSA P-256 leaf + intermediate", 1620, 78},
      {"RSA-2048 leaf + intermediate", 2890, 264},
      {"RSA-4096 full chain", 5100, 520},
      {"ML-DSA-65 leaf", 9400, 3327},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(c.name);
    const size_t target =
        realityDisguiseCertTargetDerLen(c.certificate_len, c.certificate_verify_len);
    ASSERT_NE(0u, target);
    const std::vector<uint8_t> der = config_.buildDisguiseCert(target);
    ASSERT_FALSE(der.empty());

    FlightSizes sizes;
    ASSERT_TRUE(handshakeWithLeaf(config_.ed25519PrivateKey(), der, &sizes));
    EXPECT_EQ(static_cast<size_t>(c.certificate_len) + c.certificate_verify_len,
              sizes.certificate + sizes.certificate_verify);
  }
}

} // namespace
} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
