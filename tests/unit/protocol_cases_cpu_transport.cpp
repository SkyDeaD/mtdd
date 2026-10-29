// CPU-03 transport decode regression tests.
//
// The baseline TransportDecoder::feed() copies the complete input span into the
// accumulation buffer before parsing, even when the buffer is empty and every
// frame is complete. The CPU-03 change parses complete frames directly from the
// caller's span and buffers only an incomplete tail. These tests pin both the
// observable decoding contract and the accounting properties:
//
//   * a fresh decoder that consumed only complete frames retains no buffer
//     (retained_bytes() == 0) - this is the RED regression below;
//   * every header/payload split still decodes exactly once;
//   * buffered() keeps the baseline value on incomplete tails and on protocol
//     errors (the baseline leaves the whole appended stream buffered);
//   * messages own their payload (no span into the caller's input);
//   * Status semantics including a pre-populated `out` vector are unchanged.

#include "../support/protocol_fixture.hpp"

#include <memory>
#include <random>

namespace mtdd::protocol {

namespace {

Bytes intermediate_frame(std::span<const std::uint8_t> payload, bool quick_ack = false) {
  EXPECT_EQ(payload.size() % 4, 0u);
  const auto word = static_cast<std::uint32_t>(payload.size()) |
                    (quick_ack ? 0x80000000u : 0u);
  Bytes out = le32(word);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

// Secure (padded intermediate) frame. `len` on the wire is payload + padding;
// the receiver truncates padding, so every accepted frame yields a non-empty
// 4-byte aligned payload.
Bytes secure_frame(std::span<const std::uint8_t> payload, std::size_t padding = 0,
                   bool quick_ack = false) {
  EXPECT_EQ(payload.size() % 4, 0u);
  EXPECT_LT(padding, 4u);
  const auto word = static_cast<std::uint32_t>(payload.size() + padding) |
                    (quick_ack ? 0x80000000u : 0u);
  Bytes out = le32(word);
  out.insert(out.end(), payload.begin(), payload.end());
  out.insert(out.end(), padding, 0xee);
  return out;
}

Bytes pattern(std::size_t size, std::uint8_t seed) {
  Bytes out(size);
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(seed + 17u * i);
  }
  return out;
}

using Messages = std::vector<TransportDecoder::Message>;

}  // namespace

// ------------------------ retained-buffer regression ------------------------

TEST(TransportFastPath, CompleteIntermediateFrameRetainsNoBuffer) {
  TransportDecoder dec({ProtoTag::Intermediate, 1u << 20});
  Messages msgs;
  const Bytes wire = intermediate_frame(from_hex("00112233"));

  ASSERT_EQ(dec.feed(wire, msgs), Status::Ok);
  ASSERT_EQ(msgs.size(), 1u);
  expect_bytes(msgs[0].data, from_hex("00112233"));
  EXPECT_EQ(dec.buffered(), 0u);
  // Regression: a complete frame must be decoded straight from the input span.
  EXPECT_EQ(dec.retained_bytes(), 0u);
}

TEST(TransportFastPath, CompleteSecureFrameRetainsNoBuffer) {
  TransportDecoder dec({ProtoTag::Secure, 1u << 20});
  Messages msgs;
  const Bytes wire = secure_frame(from_hex("0102030405060708"), 3);

  ASSERT_EQ(dec.feed(wire, msgs), Status::Ok);
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].data, from_hex("0102030405060708"));
  EXPECT_EQ(dec.buffered(), 0u);
  EXPECT_EQ(dec.retained_bytes(), 0u);
}

TEST(TransportFastPath, CoalescedCompleteFramesRetainNoBuffer) {
  for (const ProtoTag tag : {ProtoTag::Intermediate, ProtoTag::Secure}) {
    TransportDecoder dec({tag, 1u << 20});
    Messages msgs;
    const Bytes a = (tag == ProtoTag::Secure) ? secure_frame(from_hex("11111111"), 1)
                                              : intermediate_frame(from_hex("11111111"));
    const Bytes b = (tag == ProtoTag::Secure) ? secure_frame(from_hex("2222222222222222"), 0)
                                              : intermediate_frame(from_hex("2222222222222222"));
    const Bytes c = (tag == ProtoTag::Secure) ? secure_frame(from_hex("33333333"), 2, true)
                                              : intermediate_frame(from_hex("33333333"), true);
    const Bytes wire = cat({a, b, c});
    ASSERT_EQ(dec.feed(wire, msgs), Status::Ok);
    ASSERT_EQ(msgs.size(), 3u);
    EXPECT_EQ(msgs[0].data, from_hex("11111111"));
    EXPECT_EQ(msgs[1].data, from_hex("2222222222222222"));
    EXPECT_EQ(msgs[2].data, from_hex("33333333"));
    EXPECT_FALSE(msgs[0].quick_ack);
    EXPECT_TRUE(msgs[2].quick_ack);
    EXPECT_EQ(dec.buffered(), 0u);
    EXPECT_EQ(dec.retained_bytes(), 0u);
  }
}

TEST(TransportFastPath, RepeatedCompleteFramesKeepZeroRetention) {
  TransportDecoder dec({ProtoTag::Intermediate, 1u << 20});
  Messages msgs;
  const Bytes frame = intermediate_frame(from_hex("deadbeef"));
  for (int i = 0; i < 64; ++i) {
    ASSERT_EQ(dec.feed(frame, msgs), Status::Ok);
    ASSERT_EQ(dec.retained_bytes(), 0u) << "iteration=" << i;
  }
  ASSERT_EQ(msgs.size(), 64u);
  EXPECT_EQ(dec.buffered(), 0u);
}

TEST(TransportFastPath, EmptyFeedOnFreshDecoderAsksForMore) {
  TransportDecoder dec({ProtoTag::Intermediate, 1u << 20});
  Messages msgs;
  EXPECT_EQ(dec.feed(std::span<const std::uint8_t>{}, msgs), Status::NeedMoreData);
  EXPECT_TRUE(msgs.empty());
  EXPECT_EQ(dec.buffered(), 0u);
  EXPECT_EQ(dec.retained_bytes(), 0u);
}

// ------------------------------ split positions -----------------------------

TEST(TransportFastPath, EverySplitDecodesIntermediateOnce) {
  const Bytes payload = pattern(8, 0x40);
  const Bytes wire = intermediate_frame(payload, true);
  for (std::size_t split = 0; split <= wire.size(); ++split) {
    TransportDecoder dec({ProtoTag::Intermediate, 1u << 20});
    Messages msgs;
    const auto first = std::span<const std::uint8_t>(wire).first(split);
    const auto second = std::span<const std::uint8_t>(wire).subspan(split);
    EXPECT_NE(dec.feed(first, msgs), Status::ProtocolError) << "split=" << split;
    EXPECT_EQ(dec.feed(second, msgs), Status::Ok) << "split=" << split;
    ASSERT_EQ(msgs.size(), 1u) << "split=" << split;
    EXPECT_EQ(msgs[0].data, payload) << "split=" << split;
    EXPECT_TRUE(msgs[0].quick_ack) << "split=" << split;
    EXPECT_EQ(dec.buffered(), 0u) << "split=" << split;
  }
}

TEST(TransportFastPath, EverySplitDecodesSecurePaddingOnce) {
  const Bytes payload = pattern(12, 0x80);
  for (std::size_t padding = 0; padding < 4; ++padding) {
    const Bytes wire = secure_frame(payload, padding);
    for (std::size_t split = 0; split <= wire.size(); ++split) {
      TransportDecoder dec({ProtoTag::Secure, 1u << 20});
      Messages msgs;
      (void)dec.feed(std::span<const std::uint8_t>(wire).first(split), msgs);
      EXPECT_EQ(dec.feed(std::span<const std::uint8_t>(wire).subspan(split), msgs), Status::Ok)
          << "padding=" << padding << " split=" << split;
      ASSERT_EQ(msgs.size(), 1u) << "padding=" << padding << " split=" << split;
      EXPECT_EQ(msgs[0].data, payload) << "padding=" << padding << " split=" << split;
      EXPECT_EQ(dec.buffered(), 0u);
    }
  }
}

TEST(TransportFastPath, ByteAtATimeAcrossTwoFrames) {
  for (const ProtoTag tag : {ProtoTag::Intermediate, ProtoTag::Secure}) {
    const Bytes a = (tag == ProtoTag::Secure) ? secure_frame(pattern(4, 0x11), 1)
                                              : intermediate_frame(pattern(4, 0x11));
    const Bytes b = (tag == ProtoTag::Secure) ? secure_frame(pattern(8, 0x22), 3)
                                              : intermediate_frame(pattern(8, 0x22), true);
    const Bytes wire = cat({a, b});
    TransportDecoder dec({tag, 1u << 20});
    Messages msgs;
    for (std::size_t i = 0; i < wire.size(); ++i) {
      EXPECT_NE(dec.feed(std::span<const std::uint8_t>(wire).subspan(i, 1), msgs),
                Status::ProtocolError)
          << "byte=" << i;
    }
    ASSERT_EQ(msgs.size(), 2u);
    EXPECT_EQ(msgs[0].data, pattern(4, 0x11));
    EXPECT_EQ(msgs[1].data, pattern(8, 0x22));
    EXPECT_EQ(dec.buffered(), 0u);
  }
}

// --------------------------- coalesced frame + tail --------------------------

TEST(TransportFastPath, BuffersOnlyIncompleteTail) {
  TransportDecoder dec({ProtoTag::Intermediate, 1u << 20});
  const Bytes p1 = from_hex("01020304");
  const Bytes p2 = from_hex("05060708090a0b0c");
  const Bytes wire = cat({intermediate_frame(p1), intermediate_frame(p2, true)});
  const std::size_t first_frame_size = 8;
  const std::size_t tail = 5;  // header + 1 payload byte of frame 2
  const std::size_t cut = first_frame_size + tail;

  Messages msgs;
  ASSERT_EQ(dec.feed(std::span<const std::uint8_t>(wire).first(cut), msgs), Status::Ok);
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].data, p1);
  EXPECT_EQ(dec.buffered(), tail);
  EXPECT_GE(dec.retained_bytes(), dec.buffered());

  // The tail is completed by the next feed and decoded from the buffer path.
  ASSERT_EQ(dec.feed(std::span<const std::uint8_t>(wire).subspan(cut), msgs), Status::Ok);
  ASSERT_EQ(msgs.size(), 2u);
  EXPECT_EQ(msgs[1].data, p2);
  EXPECT_TRUE(msgs[1].quick_ack);
  EXPECT_EQ(dec.buffered(), 0u);
}

TEST(TransportFastPath, PartialHeaderTailKeepsBaselineBufferedCount) {
  TransportDecoder dec({ProtoTag::Intermediate, 1u << 20});
  Messages msgs;
  const Bytes frame = intermediate_frame(from_hex("aabbccdd"));
  ASSERT_EQ(dec.feed(std::span<const std::uint8_t>(frame).first(3), msgs), Status::NeedMoreData);
  EXPECT_EQ(dec.buffered(), 3u);
  ASSERT_EQ(dec.feed(std::span<const std::uint8_t>(frame).subspan(3), msgs), Status::Ok);
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].data, from_hex("aabbccdd"));
  EXPECT_EQ(dec.buffered(), 0u);
}

TEST(TransportFastPath, ReleaseIdleKeepsPartialFrame) {
  TransportDecoder dec({ProtoTag::Intermediate, 1u << 20});
  Messages msgs;
  const Bytes frame = intermediate_frame(from_hex("0a0b0c0d"));
  ASSERT_EQ(dec.feed(std::span<const std::uint8_t>(frame).first(6), msgs), Status::NeedMoreData);
  ASSERT_EQ(dec.buffered(), 6u);
  dec.release_idle();
  EXPECT_EQ(dec.buffered(), 6u);
  ASSERT_EQ(dec.feed(std::span<const std::uint8_t>(frame).subspan(6), msgs), Status::Ok);
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].data, from_hex("0a0b0c0d"));
  dec.release_idle();
  EXPECT_EQ(dec.buffered(), 0u);
  EXPECT_EQ(dec.retained_bytes(), 0u);
}

// ----------------------------- length boundaries ----------------------------

TEST(TransportFastPath, AcceptsExactMaxMessageAndRejectsOneMore) {
  constexpr std::size_t kMax = 16;
  {
    TransportDecoder dec({ProtoTag::Intermediate, kMax});
    Messages msgs;
    const Bytes wire = intermediate_frame(pattern(kMax, 0x01));
    EXPECT_EQ(rd32(wire) & 0x7fffffffu, kMax);
    EXPECT_EQ(dec.feed(wire, msgs), Status::Ok);
    ASSERT_EQ(msgs.size(), 1u);
    EXPECT_EQ(msgs[0].data, pattern(kMax, 0x01));
  }
  {
    TransportDecoder dec({ProtoTag::Intermediate, kMax});
    Messages msgs;
    const Bytes wire = intermediate_frame(pattern(kMax + 4, 0x01));
    EXPECT_EQ(dec.feed(wire, msgs), Status::ProtocolError);
    EXPECT_TRUE(msgs.empty());
  }
  {
    TransportDecoder dec({ProtoTag::Intermediate, kMax});
    Messages msgs;
    EXPECT_EQ(dec.feed(le32(0), msgs), Status::ProtocolError);
  }
}

TEST(TransportFastPath, SecurePaddingBoundaries) {
  // len 1..3 is all padding: rejected without emitting anything. Each case uses
  // a fresh decoder because a protocol error intentionally keeps the stream
  // buffered for inspection.
  for (std::uint32_t len = 1; len < 4; ++len) {
    TransportDecoder dec({ProtoTag::Secure, 64});
    Messages msgs;
    Bytes wire = le32(len);
    wire.insert(wire.end(), len, 0xaa);
    EXPECT_EQ(dec.feed(wire, msgs), Status::ProtocolError) << "len=" << len;
    EXPECT_TRUE(msgs.empty()) << "len=" << len;
    EXPECT_EQ(dec.buffered(), wire.size()) << "len=" << len;
  }
  // len 4 (no padding) and len 7 (3 padding bytes) are accepted.
  for (std::uint32_t len = 4; len < 8; ++len) {
    TransportDecoder fresh({ProtoTag::Secure, 64});
    Messages out;
    Bytes wire = le32(len);
    for (std::uint32_t i = 0; i < len; ++i) {
      wire.push_back(static_cast<std::uint8_t>(0x10 + i));
    }
    EXPECT_EQ(fresh.feed(wire, out), Status::Ok) << "len=" << len;
    ASSERT_EQ(out.size(), 1u) << "len=" << len;
    const std::size_t keep = len - (len % 4);
    EXPECT_EQ(out[0].data.size(), keep) << "len=" << len;
    EXPECT_EQ(out[0].data[0], 0x10) << "len=" << len;
  }
}

TEST(TransportFastPath, IntermediateRejectsMisalignedLength) {
  TransportDecoder dec({ProtoTag::Intermediate, 64});
  Messages msgs;
  Bytes wire = le32(6);
  wire.insert(wire.end(), 8, 0x55);  // enough bytes, but the length is invalid
  EXPECT_EQ(dec.feed(wire, msgs), Status::ProtocolError);
  EXPECT_TRUE(msgs.empty());
  EXPECT_EQ(dec.buffered(), wire.size());
}

// ---------------------- error after a successfully read frame --------------

TEST(TransportFastPath, ProtocolErrorAfterGoodFrameKeepsBaselineBufferedBytes) {
  TransportDecoder dec({ProtoTag::Intermediate, 64});
  Messages msgs;
  const Bytes good = intermediate_frame(from_hex("01020304"));
  const Bytes wire = cat({good, le32(0)});

  EXPECT_EQ(dec.feed(wire, msgs), Status::ProtocolError);
  ASSERT_EQ(msgs.size(), 1u) << "already decoded frames stay delivered";
  EXPECT_EQ(msgs[0].data, from_hex("01020304"));
  // Baseline behaviour: an error returns before the prefix erase, so the whole
  // appended stream remains observable through buffered().
  EXPECT_EQ(dec.buffered(), wire.size());
  EXPECT_GE(dec.retained_bytes(), wire.size());
}

TEST(TransportFastPath, PaddingErrorAfterGoodFrameKeepsBaselineBufferedBytes) {
  TransportDecoder dec({ProtoTag::Secure, 64});
  Messages msgs;
  const Bytes good = secure_frame(from_hex("11223344"), 2);
  Bytes bad = le32(3);
  bad.insert(bad.end(), 3, 0xee);
  const Bytes wire = cat({good, bad});

  EXPECT_EQ(dec.feed(wire, msgs), Status::ProtocolError);
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].data, from_hex("11223344"));
  EXPECT_EQ(dec.buffered(), wire.size());
}

TEST(TransportFastPath, ErrorWithExistingTailKeepsBaselineBufferedBytes) {
  TransportDecoder dec({ProtoTag::Intermediate, 64});
  Messages msgs;
  const Bytes prefix = {0, 0, 0};  // first three bytes of a zero length word
  ASSERT_EQ(dec.feed(prefix, msgs), Status::NeedMoreData);
  ASSERT_EQ(dec.buffered(), 3u);

  const Bytes zero = {0};
  EXPECT_EQ(dec.feed(zero, msgs), Status::ProtocolError);
  EXPECT_TRUE(msgs.empty());
  EXPECT_EQ(dec.buffered(), 4u);
}

// --------------------------- existing output vector ------------------------

TEST(TransportFastPath, PrepopulatedOutputKeepsStatusAndOrder) {
  TransportDecoder dec({ProtoTag::Intermediate, 64});
  Messages msgs(2);
  msgs[0].data = from_hex("aaaaaaaa");
  msgs[1].data = from_hex("bbbbbbbb");
  msgs[1].quick_ack = true;

  // Only an incomplete tail: baseline returns Ok because `out` is non-empty.
  const Bytes frame = intermediate_frame(from_hex("cccccccc"));
  EXPECT_EQ(dec.feed(std::span<const std::uint8_t>(frame).first(5), msgs), Status::Ok);
  EXPECT_EQ(msgs.size(), 2u);
  EXPECT_EQ(dec.buffered(), 5u);

  EXPECT_EQ(dec.feed(std::span<const std::uint8_t>(frame).subspan(5), msgs), Status::Ok);
  ASSERT_EQ(msgs.size(), 3u);
  EXPECT_EQ(msgs[0].data, from_hex("aaaaaaaa"));
  EXPECT_TRUE(msgs[1].quick_ack);
  EXPECT_EQ(msgs[2].data, from_hex("cccccccc"));
}

// ------------------------------- ownership --------------------------------

TEST(TransportFastPath, MessageOwnsPayloadAfterInputDestruction) {
  Messages msgs;
  {
    auto wire = std::make_unique<Bytes>(intermediate_frame(pattern(32, 0x30)));
    TransportDecoder dec({ProtoTag::Intermediate, 1u << 20});
    ASSERT_EQ(dec.feed(*wire, msgs), Status::Ok);
    ASSERT_EQ(msgs.size(), 1u);
  }
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].data, pattern(32, 0x30));
}

TEST(TransportFastPath, MessageDoesNotAliasMutableInput) {
  TransportDecoder dec({ProtoTag::Secure, 1u << 20});
  Messages msgs;
  Bytes wire = secure_frame(pattern(16, 0x50), 1);
  ASSERT_EQ(dec.feed(wire, msgs), Status::Ok);
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].data, pattern(16, 0x50));

  std::fill(wire.begin(), wire.end(), 0);
  EXPECT_EQ(msgs[0].data, pattern(16, 0x50));
  EXPECT_EQ(dec.buffered(), 0u);
}

// --------------------------- randomized segmentation -----------------------

TEST(TransportFastPath, RandomSegmentationMatchesReference) {
  std::mt19937 rng(0x43505533u);  // "CPU3"
  std::uniform_int_distribution<std::size_t> chunk(1, 9);

  for (const ProtoTag tag : {ProtoTag::Intermediate, ProtoTag::Secure}) {
    std::vector<Bytes> expected;
    Bytes wire;
    for (int i = 0; i < 40; ++i) {
      const std::size_t size = 4u * static_cast<std::size_t>(1 + (i % 5));
      const Bytes payload = pattern(size, static_cast<std::uint8_t>(i));
      expected.push_back(payload);
      wire = cat({wire, tag == ProtoTag::Secure
                            ? secure_frame(payload, static_cast<std::size_t>(i % 4),
                                           (i % 7) == 0)
                            : intermediate_frame(payload, (i % 7) == 0)});
    }

    TransportDecoder dec({tag, 1u << 20});
    Messages msgs;
    std::size_t offset = 0;
    while (offset < wire.size()) {
      const std::size_t take = std::min(chunk(rng), wire.size() - offset);
      const Status status =
          dec.feed(std::span<const std::uint8_t>(wire).subspan(offset, take), msgs);
      EXPECT_NE(status, Status::ProtocolError) << "offset=" << offset;
      offset += take;
    }
    ASSERT_EQ(msgs.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
      EXPECT_EQ(msgs[i].data, expected[i]) << "message=" << i;
      EXPECT_EQ(msgs[i].quick_ack, (i % 7) == 0) << "message=" << i;
    }
    EXPECT_EQ(dec.buffered(), 0u);
  }
}

// ------------------- header-only versus payload-complete parity -------------
//
// The baseline checks the declared length (zero / above the limit) as soon as
// the 4-byte header is present, but checks 4-byte alignment (Intermediate) and
// all-padding rejection (Secure) only once the declared payload is complete.
// An incomplete frame must therefore report NeedMoreData with the same
// buffered() count, never ProtocolError.

TEST(TransportParity, MisalignedIntermediateHeaderAloneNeedsMoreData) {
  TransportDecoder dec({ProtoTag::Intermediate, 64});
  Messages msgs;
  EXPECT_EQ(dec.feed(le32(6), msgs), Status::NeedMoreData);
  EXPECT_TRUE(msgs.empty());
  EXPECT_EQ(dec.buffered(), 4u);
  EXPECT_GE(dec.retained_bytes(), dec.buffered());
}

TEST(TransportParity, SecureAllPaddingHeaderAloneNeedsMoreData) {
  for (const std::uint32_t word : {3u, 0x80000003u, 2u, 1u}) {
    TransportDecoder dec({ProtoTag::Secure, 64});
    Messages msgs;
    EXPECT_EQ(dec.feed(le32(word), msgs), Status::NeedMoreData) << "word=" << word;
    EXPECT_TRUE(msgs.empty());
    EXPECT_EQ(dec.buffered(), 4u) << "word=" << word;
  }
}

TEST(TransportParity, MisalignedIntermediateEveryIncompletePrefixNeedsMoreData) {
  const Bytes frame = cat({le32(6), pattern(6, 0x5a)});
  ASSERT_EQ(frame.size(), 10u);
  for (std::size_t prefix = 0; prefix < frame.size(); ++prefix) {
    TransportDecoder dec({ProtoTag::Intermediate, 64});
    Messages msgs;
    EXPECT_EQ(dec.feed(std::span<const std::uint8_t>(frame).first(prefix), msgs),
              Status::NeedMoreData)
        << "prefix=" << prefix;
    EXPECT_TRUE(msgs.empty()) << "prefix=" << prefix;
    EXPECT_EQ(dec.buffered(), prefix) << "prefix=" << prefix;
  }
  TransportDecoder dec({ProtoTag::Intermediate, 64});
  Messages msgs;
  EXPECT_EQ(dec.feed(frame, msgs), Status::ProtocolError);
  EXPECT_TRUE(msgs.empty());
  EXPECT_EQ(dec.buffered(), frame.size());
}

TEST(TransportParity, SecureAllPaddingEveryIncompletePrefixNeedsMoreData) {
  const Bytes frame = cat({le32(3), pattern(3, 0x33)});
  ASSERT_EQ(frame.size(), 7u);
  for (std::size_t prefix = 0; prefix < frame.size(); ++prefix) {
    TransportDecoder dec({ProtoTag::Secure, 64});
    Messages msgs;
    EXPECT_EQ(dec.feed(std::span<const std::uint8_t>(frame).first(prefix), msgs),
              Status::NeedMoreData)
        << "prefix=" << prefix;
    EXPECT_EQ(dec.buffered(), prefix) << "prefix=" << prefix;
  }
  TransportDecoder dec({ProtoTag::Secure, 64});
  Messages msgs;
  EXPECT_EQ(dec.feed(frame, msgs), Status::ProtocolError);
  EXPECT_EQ(dec.buffered(), frame.size());
}

TEST(TransportParity, GoodFrameThenIncompleteMisalignedFrame) {
  const Bytes wire = cat({intermediate_frame(from_hex("01020304")), le32(6),
                          pattern(2, 0x77)});
  ASSERT_EQ(wire.size(), 14u);
  TransportDecoder dec({ProtoTag::Intermediate, 64});
  Messages msgs;
  EXPECT_EQ(dec.feed(wire, msgs), Status::Ok);
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].data, from_hex("01020304"));
  EXPECT_EQ(dec.buffered(), 6u);  // 4-byte header + 2 of 6 declared payload bytes

  // Completing the invalid frame reaches the alignment check, and the whole
  // appended stream stays observable as in the baseline.
  EXPECT_EQ(dec.feed(pattern(4, 0x77), msgs), Status::ProtocolError);
  EXPECT_EQ(msgs.size(), 1u);
  EXPECT_EQ(dec.buffered(), 10u);
}

TEST(TransportParity, PrepopulatedOutputWithIncompleteMisalignedFrame) {
  TransportDecoder dec({ProtoTag::Intermediate, 64});
  Messages msgs(1);
  msgs[0].data = from_hex("aaaaaaaa");
  EXPECT_EQ(dec.feed(le32(6), msgs), Status::Ok);
  EXPECT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].data, from_hex("aaaaaaaa"));
  EXPECT_EQ(dec.buffered(), 4u);
}

TEST(TransportParity, OversizedHeaderRejectsBeforePayloadAndMaxLengthWaits) {
  {
    TransportDecoder dec({ProtoTag::Intermediate, 64});
    Messages msgs;
    EXPECT_EQ(dec.feed(le32(65), msgs), Status::ProtocolError);
    EXPECT_EQ(dec.buffered(), 4u);
  }
  {
    // len == max_message with an incomplete payload waits for more bytes.
    TransportDecoder dec({ProtoTag::Intermediate, 64});
    Messages msgs;
    EXPECT_EQ(dec.feed(le32(64), msgs), Status::NeedMoreData);
    EXPECT_EQ(dec.buffered(), 4u);
  }
}

// ------------------- fast path versus legacy fragmented branch --------------
//
// When buffer_ is empty the decoder parses the caller's span directly. Once a
// tail is buffered it uses the explicit 75713d0 append -> inline parse -> erase
// loop. The two branches are separate code on purpose: the fragmented path must
// keep the baseline shape and cost, so it must not be routed through the fast
// path helpers. These tests force the legacy branch by splitting every stream
// at every offset (splits of 1..3 bytes also prove the first feed only primed
// the buffer) and require identical Status, messages and quick-ACK flags, plus
// pinned absolute expectations, so the two branches cannot drift together.
//
// buffered() is compared as well, with one baseline rule: a protocol error
// returns before the consumed prefix is erased, so the reported count is every
// byte fed since the last successful erase. That value legitimately depends on
// where a feed boundary falls; the tests compute it from the split instead of
// assuming a single constant.

namespace {

struct Expectation {
  Status status{Status::NeedMoreData};
  std::size_t buffered{0};
  std::vector<Bytes> data;
  std::vector<bool> acks;
};

struct BranchCase {
  const char* name;
  ProtoTag tag;
  std::size_t max_message;
  Bytes stream;
  Expectation expected;
  // Offset of the first invalid frame; buffered() after a byte-at-a-time error
  // is the stream size minus everything erased before that frame.
  std::size_t error_offset{0};
};

struct Outcome {
  Status status{Status::NeedMoreData};
  std::size_t first_feed_buffered{0};
  std::size_t buffered{0};
  std::size_t retained{0};
  std::vector<Bytes> data;
  std::vector<bool> acks;
};

Outcome collect(Status status, TransportDecoder& decoder,
                const std::vector<TransportDecoder::Message>& messages) {
  Outcome out;
  out.status = status;
  out.buffered = decoder.buffered();
  out.retained = decoder.retained_bytes();
  for (const auto& message : messages) {
    out.data.push_back(message.data);
    out.acks.push_back(message.quick_ack);
  }
  return out;
}

Outcome run_whole(const BranchCase& test) {
  TransportDecoder decoder({test.tag, test.max_message});
  std::vector<TransportDecoder::Message> messages;
  const Status status = decoder.feed(test.stream, messages);
  return collect(status, decoder, messages);
}

// Feeds `prefix` bytes first (priming the accumulation buffer) and the rest
// second, so every frame is parsed by the legacy fragmented loop.
Outcome run_split(const BranchCase& test, std::size_t prefix) {
  TransportDecoder decoder({test.tag, test.max_message});
  std::vector<TransportDecoder::Message> messages;
  (void)decoder.feed(std::span<const std::uint8_t>(test.stream).first(prefix), messages);
  const std::size_t first_feed_buffered = decoder.buffered();
  const Status status =
      decoder.feed(std::span<const std::uint8_t>(test.stream).subspan(prefix), messages);
  Outcome out = collect(status, decoder, messages);
  out.first_feed_buffered = first_feed_buffered;
  return out;
}

void expect_payloads(const Outcome& actual, const Expectation& expected, const char* branch,
                     const char* name) {
  EXPECT_EQ(actual.status, expected.status) << name << " branch=" << branch;
  ASSERT_EQ(actual.data.size(), expected.data.size()) << name << " branch=" << branch;
  for (std::size_t i = 0; i < expected.data.size(); ++i) {
    EXPECT_EQ(actual.data[i], expected.data[i]) << name << " branch=" << branch
                                                << " message=" << i;
    EXPECT_EQ(actual.acks[i], expected.acks[i]) << name << " branch=" << branch
                                                << " message=" << i;
  }
  EXPECT_GE(actual.retained, actual.buffered) << name << " branch=" << branch;
}

std::vector<BranchCase> branch_cases() {
  const Bytes p4 = from_hex("11111111");
  const Bytes p8 = from_hex("2222222222222222");
  const Bytes p12 = from_hex("333333333333333333333333");
  const Bytes good_intermediate = intermediate_frame(p4);
  const Bytes good_secure = secure_frame(p8, 2);
  Bytes partial_second = intermediate_frame(p8);
  partial_second.resize(5);
  const Bytes incomplete_second = partial_second;
  Bytes incomplete_only = intermediate_frame(p8);
  incomplete_only.resize(7);
  constexpr std::size_t kMax = 64;

  std::vector<BranchCase> cases;
  cases.push_back({"intermediate_frame", ProtoTag::Intermediate, kMax, good_intermediate,
                   {Status::Ok, 0, {p4}, {false}}, 0});
  cases.push_back({"intermediate_quick_ack", ProtoTag::Intermediate, kMax,
                   intermediate_frame(p8, true), {Status::Ok, 0, {p8}, {true}}, 0});
  cases.push_back({"secure_padded", ProtoTag::Secure, kMax, good_secure,
                   {Status::Ok, 0, {p8}, {false}}, 0});
  cases.push_back({"coalesced", ProtoTag::Secure, kMax,
                   cat({secure_frame(p4, 1), secure_frame(p8, 3, true), secure_frame(p12, 0)}),
                   {Status::Ok, 0, {p4, p8, p12}, {false, true, false}}, 0});
  cases.push_back({"complete_plus_tail", ProtoTag::Intermediate, kMax,
                   cat({intermediate_frame(p4), incomplete_second}),
                   {Status::Ok, 5, {p4}, {false}}, 0});
  cases.push_back({"incomplete_only", ProtoTag::Intermediate, kMax, incomplete_only,
                   {Status::NeedMoreData, 7, {}, {}}, 0});
  cases.push_back({"good_then_zero_length", ProtoTag::Intermediate, kMax,
                   cat({intermediate_frame(p4), le32(0)}),
                   {Status::ProtocolError, 12, {p4}, {false}}, 8});
  cases.push_back({"good_then_complete_misaligned", ProtoTag::Intermediate, kMax,
                   cat({intermediate_frame(p4), le32(6), pattern(6, 0x5a)}),
                   {Status::ProtocolError, 18, {p4}, {false}}, 8});
  cases.push_back({"misaligned_header_only", ProtoTag::Intermediate, kMax, le32(6),
                   {Status::NeedMoreData, 4, {}, {}}, 0});
  cases.push_back({"good_then_incomplete_misaligned", ProtoTag::Intermediate, kMax,
                   cat({intermediate_frame(p4), le32(6), pattern(2, 0x5a)}),
                   {Status::Ok, 6, {p4}, {false}}, 0});
  cases.push_back({"secure_all_padding", ProtoTag::Secure, kMax, cat({le32(3), pattern(3, 0x33)}),
                   {Status::ProtocolError, 7, {}, {}}, 0});
  cases.push_back({"secure_padding_header_only", ProtoTag::Secure, kMax, le32(3),
                   {Status::NeedMoreData, 4, {}, {}}, 0});
  cases.push_back({"oversized_header", ProtoTag::Intermediate, kMax, le32(kMax + 1),
                   {Status::ProtocolError, 4, {}, {}}, 0});
  cases.push_back({"max_length_incomplete", ProtoTag::Intermediate, kMax,
                   cat({le32(kMax), pattern(4, 0x44)}), {Status::NeedMoreData, 8, {}, {}}, 0});
  return cases;
}

}  // namespace

TEST(TransportBranches, FastAndBufferedPathsAgreeOnEverySplit) {
  for (const auto& test : branch_cases()) {
    const Outcome fast = run_whole(test);
    expect_payloads(fast, test.expected, "fast", test.name);
    EXPECT_EQ(fast.buffered, test.expected.buffered) << test.name;
    EXPECT_EQ(fast.first_feed_buffered, 0u) << test.name;

    for (std::size_t prefix = 1; prefix < test.stream.size(); ++prefix) {
      const Outcome buffered = run_split(test, prefix);
      expect_payloads(buffered, test.expected, "buffered", test.name);
      if (prefix < 4) {
        // A 1..3 byte first feed must only prime the accumulation buffer, which
        // is exactly the legacy branch precondition.
        EXPECT_EQ(buffered.first_feed_buffered, prefix)
            << test.name << " prefix=" << prefix;
      }
      if (buffered.status == Status::ProtocolError) {
        const std::size_t erased = prefix - buffered.first_feed_buffered;
        EXPECT_EQ(buffered.buffered, test.stream.size() - erased)
            << test.name << " prefix=" << prefix;
      } else {
        EXPECT_EQ(buffered.buffered, fast.buffered) << test.name << " prefix=" << prefix;
      }
      EXPECT_EQ(buffered.data.size(), fast.data.size()) << test.name << " prefix=" << prefix;
    }
  }
}

TEST(TransportBranches, ByteAtATimeUsesBufferedPathAndMatchesWholeFeed) {
  for (const auto& test : branch_cases()) {
    TransportDecoder decoder({test.tag, test.max_message});
    std::vector<TransportDecoder::Message> messages;
    Status status = Status::NeedMoreData;
    for (std::size_t i = 0; i < test.stream.size(); ++i) {
      status = decoder.feed(std::span<const std::uint8_t>(test.stream).subspan(i, 1), messages);
    }
    const Outcome bytewise = collect(status, decoder, messages);
    const Outcome fast = run_whole(test);
    expect_payloads(bytewise, test.expected, "bytewise", test.name);
    if (bytewise.status == Status::ProtocolError) {
      EXPECT_EQ(bytewise.buffered, test.stream.size() - test.error_offset) << test.name;
    } else {
      EXPECT_EQ(bytewise.buffered, fast.buffered) << test.name;
    }
    ASSERT_EQ(bytewise.data.size(), fast.data.size()) << test.name;
    for (std::size_t i = 0; i < fast.data.size(); ++i) {
      EXPECT_EQ(bytewise.data[i], fast.data[i]) << test.name << " message=" << i;
      EXPECT_EQ(bytewise.acks[i], fast.acks[i]) << test.name << " message=" << i;
    }
  }
}

TEST(TransportBranches, BufferedPathOwnsPayloadAndRetainedTail) {
  const Bytes frame = intermediate_frame(pattern(24, 0x60));
  TransportDecoder decoder({ProtoTag::Intermediate, 1u << 20});
  std::vector<TransportDecoder::Message> messages;

  {
    auto first = std::make_unique<Bytes>(frame.begin(), frame.begin() + 7);
    ASSERT_EQ(decoder.feed(*first, messages), Status::NeedMoreData);
    EXPECT_EQ(decoder.buffered(), 7u);
  }
  // The caller's bytes are gone; the buffered tail must own its copy and the
  // decoded payload must outlive the second input buffer as well.
  {
    auto second = std::make_unique<Bytes>(frame.begin() + 7, frame.end());
    ASSERT_EQ(decoder.feed(*second, messages), Status::Ok);
  }
  ASSERT_EQ(messages.size(), 1u);
  EXPECT_EQ(messages[0].data, pattern(24, 0x60));
  EXPECT_EQ(decoder.buffered(), 0u);
}

}  // namespace mtdd::protocol
