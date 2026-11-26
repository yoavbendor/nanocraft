// SPDX-License-Identifier: Apache-2.0
// pcap / pcapng writers, read back by two independent readers: nanocraft's strict reader and
// nanom_shark's block scanner. Also writes the files the python oracle (dpkt + scapy) checks.
#include <nanocraft/nanocraft.hpp>
#include <nanom_shark/pcap.hpp>

#include "check.hpp"
#include "reference.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <string>

using namespace nanocraft::proto;

struct rec {
  std::uint64_t ts;
  std::uint32_t iface;
  ref::bytes data;
  std::uint32_t origlen;
  std::optional<std::uint32_t> flags;
  std::string comment;
};

static auto make_template() {
  return nanocraft::compile(eth{.dst = {0x01, 0x00, 0x5e, 0, 0, 1}, .src = {2, 0, 0, 0, 0, 0xaa}} /
                            vlan{.vid = 100, .pcp = 3} /
                            ipv4{.src = {10, 0, 0, 1}, .dst = {239, 0, 0, 1}} / udp{.src_port = 30501, .dst_port = 30501} /
                            someip{.service_id = 0x1234, .method_id = 0x8001, .client_id = 1});
}

// Frames: template frames (crafted in the writer buffer) and SOME/IP-TP segments (gathers).
template <class W>
static std::vector<rec> produce(W&& write_frame, std::size_t n, std::uint64_t ts0) {
  auto tm = make_template();
  auto tp = nanocraft::compile(eth{} / ipv4{.src = {10, 0, 0, 1}, .dst = {10, 0, 0, 2}} / udp{.src_port = 1, .dst_port = 2} /
                               someip{.service_id = 7} / someip_tp{});
  nanocraft::segmenter seg(tp, someip_tp_segments(1392));
  std::vector<rec> out;
  std::uint64_t ts = ts0;
  for (std::size_t i = 0; i < n; ++i) {
    ts += t::rnd(1, 3000000);
    tm.set<"someip.session_id">(i & 0xffff);
    tm.set<"ipv4.identification">(i & 0xffff);
    const auto pay = t::random_bytes(t::rnd(0, 1400));
    ref::bytes f(tm.frame_size(pay.size()));
    f.resize(tm.write(f, pay));
    out.push_back({ts, 0, f, std::uint32_t(f.size()), {}, {}});
    write_frame(out.back(), &tm, std::span<const std::byte>(pay), nullptr);
    if (i % 50 == 0) {
      const auto msg = t::random_bytes(t::rnd(1, 9000));
      tp.set<"someip.session_id">(i & 0xffff);
      seg.run(msg, [&](const nanocraft::gather& g) {
        ts += 1000;
        ref::bytes fl(g.size());
        g.copy_to(fl);
        out.push_back({ts, 0, fl, std::uint32_t(fl.size()), {}, {}});
        write_frame(out.back(), static_cast<decltype(&tm)>(nullptr), std::span<const std::byte>{}, &g);
      });
    }
  }
  return out;
}

static std::vector<rec> read_all(std::span<const std::byte> file, std::string& err) {
  nanocraft::capture_reader r(file);
  std::vector<rec> v;
  nanocraft::packet p;
  while (r.next(p))
    v.push_back({p.ts_ns, p.interface, ref::bytes(p.data.begin(), p.data.end()), p.origlen, p.flags,
                 std::string(p.comment)});
  err = std::string(r.error());
  return v;
}

// nanom_shark's scanner: block boundaries + EPB/record parse
static std::vector<ref::bytes> shark_read(std::span<const std::byte> file, std::vector<std::uint64_t>* ts_raw = nullptr) {
  std::vector<nmpcap::BlockRef> refs;
  std::string err;
  std::vector<ref::bytes> v;
  if (!nmpcap::scan_blocks(file, refs, err)) {
    t::fail(__FILE__, __LINE__, "nanom_shark scan_blocks: " + err);
    return v;
  }
  for (const auto& r : refs) {
    nmpcap::EpbView e;
    if (r.kind != nmpcap::Kind::Epb && r.kind != nmpcap::Kind::PcapRecord) continue;
    if (!nmpcap::parse_epb(file, r, e)) {
      t::fail(__FILE__, __LINE__, "nanom_shark parse_epb");
      continue;
    }
    v.emplace_back(file.begin() + std::ptrdiff_t(e.payload_file_offset),
                   file.begin() + std::ptrdiff_t(e.payload_file_offset + e.caplen));
    if (ts_raw) ts_raw->push_back(e.ts_raw);
  }
  return v;
}

// The python oracle's expectations: "<file> <frames>" per line.
static void manifest(const std::string& dir, const char* file, std::size_t frames) {
  std::FILE* mf = std::fopen((dir + "/nanocraft_manifest.txt").c_str(), "a");
  if (!mf) return;
  std::fprintf(mf, "%s %zu\n", file, frames);
  std::fclose(mf);
}

static void test_pcap(bool ns, std::size_t bufsize, const std::string& dir) {
  std::vector<std::byte> file;
  std::vector<rec> want;
  {
    nanocraft::pcap_writer w(nanocraft::output::buffer(file), {.nanosecond = ns, .buffer_size = bufsize});
    want = produce(
        [&](const rec& r, auto* tm, std::span<const std::byte> pay, const nanocraft::gather* g) {
          if (tm) CHECK(w.write(r.ts, *tm, pay));
          else CHECK(w.write(r.ts, *g));
        },
        400, 1700000000ull * 1000000000ull);
    CHECK(w.flush());
    CHECK_EQ(w.frames(), want.size());
  }
  std::string err;
  const auto got = read_all(file, err);
  CHECK_MSG(err.empty(), err);
  CHECK_EQ(got.size(), want.size());
  for (std::size_t i = 0; i < got.size() && i < want.size(); ++i) {
    CHECK_BYTES(got[i].data, want[i].data);
    const std::uint64_t res = ns ? 1 : 1000;
    CHECK_EQ(got[i].ts, want[i].ts / res * res);
    CHECK(ref::verify(got[i].data).udp_ok);
  }
  std::vector<std::uint64_t> raw;
  const auto sh = shark_read(file, &raw);
  CHECK_EQ(sh.size(), want.size());
  for (std::size_t i = 0; i < sh.size() && i < want.size(); ++i) {
    CHECK_BYTES(sh[i], want[i].data);
    CHECK_EQ(raw[i] >> 32, want[i].ts / 1000000000u);
    CHECK_EQ(raw[i] & 0xffffffffu, (want[i].ts % 1000000000u) / (ns ? 1 : 1000));
  }
  if (!dir.empty()) {
    const std::string path = dir + (ns ? "/nanocraft_ns.pcap" : "/nanocraft_us.pcap");
    std::FILE* f = std::fopen(path.c_str(), "wb");
    CHECK(f != nullptr);
    if (f) {
      std::fwrite(file.data(), 1, file.size(), f);
      std::fclose(f);
    }
    manifest(dir, ns ? "nanocraft_ns.pcap" : "nanocraft_us.pcap", want.size());
  }
}

static void test_pcapng(std::size_t bufsize, const std::string& dir) {
  std::vector<std::byte> file;
  std::vector<rec> want;
  {
    nanocraft::pcapng_writer w(nanocraft::output::buffer(file), bufsize);
    const auto i0 = w.add_interface({.linktype = 1, .name = "veth0", .description = "nanocraft test", .tsresol = 9});
    const auto i1 = w.add_interface({.linktype = 1, .name = "eth1", .tsresol = 6});
    CHECK_EQ(i0, 0u);
    CHECK_EQ(i1, 1u);
    std::size_t k = 0;
    want = produce(
        [&](rec& r, auto* tm, std::span<const std::byte> pay, const nanocraft::gather* g) {
          r.iface = (k % 3 == 2) ? i1 : i0;
          nanocraft::epb_options o;
          if (k % 4 == 1) r.flags = o.flags = std::uint32_t(1 + (k % 2));
          if (k % 7 == 3) r.comment = "frame " + std::to_string(k) + (k % 2 ? "!" : "");
          o.comment = r.comment;
          if (tm) CHECK(w.write(r.iface, r.ts, *tm, pay, o));
          else CHECK(w.write(r.iface, r.ts, *g, o));
          ++k;
        },
        400, 1700000000ull * 1000000000ull + 123);
    CHECK(w.flush());
  }
  std::string err;
  nanocraft::capture_reader rd(file);
  const auto got = read_all(file, err);
  CHECK_MSG(err.empty(), err);
  CHECK_EQ(got.size(), want.size());
  for (std::size_t i = 0; i < got.size() && i < want.size(); ++i) {
    CHECK_BYTES(got[i].data, want[i].data);
    CHECK_EQ(got[i].iface, want[i].iface);
    const std::uint64_t res = want[i].iface == 1 ? 1000 : 1;
    CHECK_EQ(got[i].ts, want[i].ts / res * res);
    CHECK(got[i].flags == want[i].flags);
    CHECK(got[i].comment == want[i].comment);
  }
  {
    nanocraft::packet p;
    while (rd.next(p)) {
    }
    CHECK_EQ(rd.interfaces().size(), std::size_t(2));
    if (rd.interfaces().size() == 2) {
      CHECK(rd.interfaces()[0].name == "veth0");
      CHECK_EQ(rd.interfaces()[1].units_per_sec, 1000000u);
    }
  }
  const auto sh = shark_read(file);
  CHECK_EQ(sh.size(), want.size());
  for (std::size_t i = 0; i < sh.size() && i < want.size(); ++i) CHECK_BYTES(sh[i], want[i].data);

  // strictness: broken framing is rejected
  {
    auto bad = file;
    bad[bad.size() - 1] ^= std::byte{1};  // trailing length of the last block
    std::string e;
    read_all(bad, e);
    CHECK(!e.empty());
    auto bad2 = file;
    // first EPB's caplen (SHB and two IDBs precede it): find it by scanning
    std::size_t o = 0;
    while (o + 8 <= bad2.size()) {
      std::uint32_t ty, len;
      std::memcpy(&ty, bad2.data() + o, 4);
      std::memcpy(&len, bad2.data() + o + 4, 4);
      if (ty == 6) break;
      o += len;
    }
    std::uint32_t big = 0xfffff;
    std::memcpy(bad2.data() + o + 20, &big, 4);
    read_all(bad2, e);
    CHECK(!e.empty());
  }
  if (!dir.empty()) {
    // through a FILE* and an fd too: identical bytes
    const std::string p1 = dir + "/nanocraft.pcapng";
    const std::string p2 = dir + "/nanocraft_fd.pcapng";
    std::FILE* f = std::fopen(p1.c_str(), "wb");
    CHECK(f);
    {
      nanocraft::pcapng_writer w(nanocraft::output::file(f), 1 << 16);
      w.add_interface({.name = "veth0", .description = "nanocraft test", .tsresol = 9});
      w.add_interface({.name = "eth1", .tsresol = 6});
      for (const auto& r : want) w.write(r.iface, r.ts, r.data, {.flags = r.flags, .comment = r.comment});
    }
    std::fclose(f);
    const int fd = ::open(p2.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0);
    {
      nanocraft::pcapng_writer w(nanocraft::output::fd(fd), 1000);
      w.add_interface({.name = "veth0", .description = "nanocraft test", .tsresol = 9});
      w.add_interface({.name = "eth1", .tsresol = 6});
      for (const auto& r : want) w.write(r.iface, r.ts, r.data, {.flags = r.flags, .comment = r.comment});
    }
    ::close(fd);
    auto m1 = nanocraft::mapped_file::open(p1.c_str());
    auto m2 = nanocraft::mapped_file::open(p2.c_str());
    CHECK(m1 && m2);
    CHECK_BYTES(m1.bytes(), std::span<const std::byte>(file));
    CHECK_BYTES(m2.bytes(), std::span<const std::byte>(file));
    manifest(dir, "nanocraft.pcapng", want.size());
    manifest(dir, "nanocraft_fd.pcapng", want.size());
  }
}

static void test_snaplen() {
  std::vector<std::byte> file;
  auto tm = make_template();
  const auto pay = t::random_bytes(500);
  {
    nanocraft::pcap_writer w(nanocraft::output::buffer(file), {.nanosecond = false, .snaplen = 64});
    CHECK(w.write(5'000'001'000ull, tm, pay));
  }
  nanocraft::capture_reader r(file);
  nanocraft::packet p;
  CHECK(r.next(p));
  CHECK_EQ(p.data.size(), std::size_t(64));
  CHECK_EQ(p.origlen, std::uint32_t(tm.header_size + 500));
  CHECK_EQ(p.ts_ns, 5'000'001'000ull);
  CHECK(!r.next(p));
  CHECK(r.error().empty());
  std::vector<std::byte> png;
  {
    nanocraft::pcapng_writer w(nanocraft::output::buffer(png));
    w.add_interface({.snaplen = 61});
    CHECK(w.write(0, 1, tm, pay));
    CHECK(!w.write(5, 1, tm, pay));  // unknown interface
  }
  nanocraft::capture_reader r2(png);
  CHECK(r2.next(p));
  CHECK_EQ(p.data.size(), std::size_t(61));
  CHECK(!r2.next(p));
  CHECK(r2.error().empty());
  // a truncated file
  std::vector<std::byte> cut(png.begin(), png.end() - 3);
  nanocraft::capture_reader r3(cut);
  while (r3.next(p)) {
  }
  CHECK(!r3.error().empty());
}

static void test_pcap_audit() {
  // 1. write_buffer stays failed after output failure (reserve returns nullptr)
  {
    struct fail_sink {
      int calls = 0;
      bool fail_after = false;
    } fs;
    nanocraft::output out{&fs, [](void* c, const std::byte*, std::size_t) {
                            auto* s = static_cast<fail_sink*>(c);
                            ++s->calls;
                            return !s->fail_after;
                          }};
    nanocraft::pcap_writer w(out, {.buffer_size = 64});
    fs.fail_after = true;
    std::array<std::byte, 48> f{};
    // First write triggers flush of the 24-byte header -> fails!
    CHECK(!w.write(1, f));
    CHECK(!w.ok());
    // Subsequent small write that would fit in an empty buffer MUST STILL FAIL!
    std::array<std::byte, 4> small{};
    CHECK(!w.write(2, small));
    CHECK(w.begin(3, 4).empty());
    CHECK(!w.ok());
  }

  // 2. pending_ invalidated by flush() / add_interface() and oversized end() rejected
  {
    std::vector<std::byte> file;
    nanocraft::pcap_writer w(nanocraft::output::buffer(file));
    CHECK(!w.begin(1, 16).empty());
    CHECK(w.flush());
    CHECK(!w.end(16));
    CHECK(!w.begin(1, 16).empty());
    CHECK(!w.end(32));  // > reserved
    // Empty span with nullptr data
    CHECK(w.write(1, std::span<const std::byte>(static_cast<const std::byte*>(nullptr), 0)));
    // !ok() template rejected
    auto bad = nanocraft::compile(eth{} / ipv4{.total_length = 99} / udp{});
    CHECK(!w.write(2, bad, {}));
  }
  {
    std::vector<std::byte> file;
    nanocraft::pcapng_writer w(nanocraft::output::buffer(file));
    const auto id = w.add_interface({.name = "eth0", .tsresol = 9});
    CHECK_EQ(id, 0u);
    // Reject unsupported tsresol (> 9 or binary flag 0x80)
    CHECK_EQ(w.add_interface({.tsresol = 10}), ~0u);
    CHECK_EQ(w.add_interface({.tsresol = 0x89}), ~0u);
    // Reject option strings > 65535 bytes
    std::string huge(70000, 'x');
    CHECK_EQ(w.add_interface({.name = huge}), ~0u);
    CHECK_EQ(w.add_interface({.description = huge}), ~0u);
    CHECK(w.begin(id, 1, 16, {.comment = huge}).empty());
    // add_interface / flush invalidate pending_
    CHECK(!w.begin(id, 1, 16).empty());
    CHECK_EQ(w.add_interface({.name = "eth1", .tsresol = 6}), 1u);
    CHECK(!w.end(16));
    CHECK(!w.begin(id, 1, 16).empty());
    CHECK(w.flush());
    CHECK(!w.end(16));
    // Empty span with nullptr data & !ok() template
    CHECK(w.write(id, 1, std::span<const std::byte>(static_cast<const std::byte*>(nullptr), 0)));
    auto bad = nanocraft::compile(eth{} / ipv4{.total_length = 99} / udp{});
    CHECK(!w.write(id, 2, bad, {}));
  }
  {
    // Oversized userappl marks writer !ok()
    std::vector<std::byte> file;
    std::string huge(70000, 'u');
    nanocraft::pcapng_writer w(nanocraft::output::buffer(file), 1024, huge);
    CHECK(!w.ok());
    CHECK_EQ(w.add_interface({}), ~0u);
  }

  // 3. capture_reader strictness: SHB total < 28, opt_endofopt len != 0, error reports block start b, EPB cap wrap
  {
    auto put32 = [](std::vector<std::byte>& v, std::uint32_t x) {
      for (int i = 0; i < 4; ++i) v.push_back(std::byte((x >> (8 * i)) & 0xff));
    };
    auto put16 = [](std::vector<std::byte>& v, std::uint16_t x) {
      v.push_back(std::byte(x & 0xff));
      v.push_back(std::byte(x >> 8));
    };

    // Malformed SHB with total == 24 (< 28) inside a 32-byte buffer
    std::vector<std::byte> short_shb;
    put32(short_shb, 0x0a0d0d0au);  // type
    put32(short_shb, 24);           // total < 28!
    put32(short_shb, 0x1a2b3c4du);  // BOM
    put16(short_shb, 1);            // major
    put16(short_shb, 0);            // minor
    put32(short_shb, 0xffffffffu);  // section len low
    put32(short_shb, 24);           // trailing total == 24
    put32(short_shb, 0);            // extra bytes so buffer >= 28
    put32(short_shb, 0);
    nanocraft::capture_reader r1(short_shb);
    nanocraft::packet p;
    CHECK(!r1.next(p));
    CHECK(!r1.error().empty());
    CHECK_EQ(r1.position(), std::size_t(0));

    // Malformed opt_endofopt with len != 0 in IDB; verify error offset is block start (28)
    std::vector<std::byte> bad_opt;
    // Valid 28-byte SHB
    put32(bad_opt, 0x0a0d0d0au);
    put32(bad_opt, 28);
    put32(bad_opt, 0x1a2b3c4du);
    put16(bad_opt, 1);
    put16(bad_opt, 0);
    put32(bad_opt, 0xffffffffu);
    put32(bad_opt, 0xffffffffu);
    put32(bad_opt, 28);
    // IDB starting at offset 28 with opt_endofopt (code=0, len=4)
    const std::size_t idb_off = bad_opt.size();
    put32(bad_opt, 1);   // IDB
    put32(bad_opt, 24);  // total
    put16(bad_opt, 1);   // linktype
    put16(bad_opt, 0);   // reserved
    put32(bad_opt, 0);   // snaplen
    put16(bad_opt, 0);   // opt_endofopt
    put16(bad_opt, 4);   // INVALID non-zero length!
    put32(bad_opt, 24);  // trailing total
    nanocraft::capture_reader r2(bad_opt);
    CHECK(!r2.next(p));
    CHECK(!r2.error().empty());
    CHECK_EQ(r2.position(), idb_off);
    CHECK(r2.error().find("offset 28") != std::string_view::npos);

    // EPB with huge caplen (0xfffffffd) that would wrap 32-bit padding
    std::vector<std::byte> bad_epb;
    // Valid SHB (28 bytes)
    put32(bad_epb, 0x0a0d0d0au);
    put32(bad_epb, 28);
    put32(bad_epb, 0x1a2b3c4du);
    put16(bad_epb, 1);
    put16(bad_epb, 0);
    put32(bad_epb, 0xffffffffu);
    put32(bad_epb, 0xffffffffu);
    put32(bad_epb, 28);
    // Valid IDB (20 bytes)
    put32(bad_epb, 1);
    put32(bad_epb, 20);
    put16(bad_epb, 1);
    put16(bad_epb, 0);
    put32(bad_epb, 0);
    put32(bad_epb, 20);
    // EPB at offset 48 with cap = 0xfffffffd, orig = 0xfffffffd
    const std::size_t epb_off = bad_epb.size();
    put32(bad_epb, 6);
    put32(bad_epb, 32);
    put32(bad_epb, 0);
    put32(bad_epb, 0);
    put32(bad_epb, 0);
    put32(bad_epb, 0xfffffffdu);
    put32(bad_epb, 0xfffffffdu);
    put32(bad_epb, 32);
    nanocraft::capture_reader r3(bad_epb);
    CHECK(!r3.next(p));
    CHECK(!r3.error().empty());
    CHECK_EQ(r3.position(), epb_off);
  }
}

int main(int argc, char** argv) {
  const std::string dir = argc > 1 ? argv[1] : "";
  if (!dir.empty()) std::remove((dir + "/nanocraft_manifest.txt").c_str());
  test_pcap(false, 1 << 20, dir);
  test_pcap(true, 1 << 20, dir);
  test_pcap(true, 100, "");  // frames larger than the buffer
  test_pcapng(1 << 20, dir);
  test_pcapng(64, "");
  test_snaplen();
  test_pcap_audit();
  return t::done("test_pcap");
}
