// SPDX-License-Identifier: Apache-2.0
// nanocraft/layer.hpp — the protocol seam: what the crafting engine needs to know about a layer.
//
// A layer is a fixed-size header with a NANOM_DESCRIBE'd wire layout plus a
// nanocraft::layer_info<L> specialization that tells the engine, declaratively, which of its
// fields are lengths, which are Internet checksums, and how it links to the layer stacked on top
// of it. The engine (frame_template.hpp) is protocol-independent: it only ever reads this table.
// Two kinds of layer value are accepted:
//
//   * a described wire struct itself (`L` is nanom::Described): the image is nanom::emit(L), the
//     patch points are L's fields;
//   * a builder value (nanowire::ipv4{...}, ...): layer_info<L>::wire names the described wire
//     struct that gives the patch points, and the image is what the builder itself writes
//     (`layer_info<L>::write(l, p, ctx)` if given, else `l.write(p, ctx)` / `l.write(p)`, with a
//     nanowire::build_ctx). The builder must write exactly wire_size_v<wire> bytes.
//
//   template <> struct nanocraft::layer_info<my_hdr> {
//     static constexpr std::string_view name = "my";                       // patch path prefix
//     using wire = my_wire_hdr;                                             // builders only
//     static constexpr std::array lengths   = {length_spec{"len", 0, 0}};   // optional
//     static constexpr std::array checksums = {checksum_spec{"ck", checksum_kind::header}};  // optional
//     static constexpr pseudo_spec pseudo{...};                             // optional: an IP layer
//     static constexpr std::array selectors = {std::string_view{"type"}};  // optional: identity fields
//     static constexpr std::uint16_t ethertype = 0x88b5;  // optional: announced to the layer below
//     static constexpr std::uint8_t ip_proto = 253;       // optional: announced to the layer below
//     template <class Next> static constexpr void link(my_hdr&, const Next&);    // optional
//     static constexpr std::string_view check(const my_hdr&);   // optional: "" or why it cannot be templated
//     static constexpr bool keep_checksum(const my_hdr&);       // optional: start with csum_policy::keep
//   };
//
// Stacks are written with operator/ (`eth{} / ipv4{} / udp{}`) or nanocraft::stack{...}.
// nanocraft/nanowire_layers.hpp specializes layer_info for nanowire's builders and wire structs.
#ifndef NANOCRAFT_LAYER_HPP_INCLUDED
#define NANOCRAFT_LAYER_HPP_INCLUDED

#include <nanom/emit.hpp>
#include <nanowire/core.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <tuple>
#include <type_traits>

namespace nanocraft {

/// A length field: value = (bytes from `from` within this layer to the end of the frame's
/// payload) + add. IPv4 total_length {from 0}, UDP length {from 0}, IPv6 payload_length {from 40},
/// SOME/IP length {from 8}.
struct length_spec {
  std::string_view field;
  std::uint16_t from = 0;
  std::int32_t add = 0;
};

enum class checksum_kind : std::uint8_t {
  header,  ///< covers `cover` bytes of this layer only (IPv4 header checksum)
  l4,      ///< pseudo header of the enclosing IP layer + this layer + all after it (UDP, TCP)
};

/// An Internet-checksum field (16 bit, big endian).
struct checksum_spec {
  std::string_view field;
  checksum_kind kind = checksum_kind::header;
  std::uint16_t cover = 0;                 ///< header kind: bytes covered (0 = the whole layer)
  std::uint8_t pseudo_proto = 0;           ///< l4 kind: protocol number in the pseudo header
  std::string_view pseudo_length_field{};  ///< l4 kind: this layer's field that the pseudo header repeats
  bool map_zero_to_ffff = false;           ///< RFC 768 / RFC 8200: store computed 0x0000 as 0xFFFF (UDP, not TCP)
};

/// What an IP layer contributes to an l4 checksum's pseudo header.
struct pseudo_spec {
  std::uint16_t addr_off = 0;     ///< source + destination address bytes, contiguous
  std::uint16_t addr_len = 0;
  bool zero_checksum_ok = false;  ///< a stored 0 means "no checksum" (UDP over IPv4)
};

/// Specialize for every layer type. See the header comment for the members.
template <class L>
struct layer_info;

namespace detail {
template <class L>
struct wire_of {
  using type = L;
};
template <class L>
  requires requires { typename layer_info<L>::wire; }
struct wire_of<L> {
  using type = typename layer_info<L>::wire;
};
}  // namespace detail

/// The described wire struct that gives layer L its byte layout and patch points.
template <class L>
using wire_t = typename detail::wire_of<L>::type;

template <class L>
concept layer = requires {
  { layer_info<L>::name } -> std::convertible_to<std::string_view>;
  requires nanom::Described<wire_t<L>>;
};

/// The EtherType layer `n` announces to the layer below it (0: none). A builder's ethertype()
/// (nanowire::vlan returns its TPID) wins over layer_info<N>::ethertype.
template <class N>
constexpr std::uint16_t next_ethertype(const N& n) noexcept {
  if constexpr (requires { n.ethertype(); }) return std::uint16_t(n.ethertype());
  else if constexpr (requires { layer_info<N>::ethertype; }) return layer_info<N>::ethertype;
  else return 0;
}
/// The IP protocol number layer `n` announces to the IP / extension header below it (0: none).
template <class N>
constexpr std::uint8_t next_ip_proto(const N& n) noexcept {
  if constexpr (requires { n.ip_protocol(); }) return std::uint8_t(n.ip_protocol());
  else if constexpr (requires { layer_info<N>::ip_proto; }) return layer_info<N>::ip_proto;
  else return 0;
}

/// A list of layers, outermost first.
template <layer... L>
struct stack {
  std::tuple<L...> layers;
  constexpr stack() = default;
  constexpr explicit stack(L... l) : layers(std::move(l)...) {}
  constexpr explicit stack(std::tuple<L...> t) : layers(std::move(t)) {}
};
template <class... L>
stack(L...) -> stack<L...>;

/// Stack composition: eth{} / ipv4{} / udp{}.
template <layer A, layer B>
constexpr stack<A, B> operator/(A a, B b) {
  return stack<A, B>(std::move(a), std::move(b));
}
template <layer... L, layer B>
constexpr stack<L..., B> operator/(stack<L...> s, B b) {
  return stack<L..., B>(std::tuple_cat(std::move(s.layers), std::tuple<B>(std::move(b))));
}

namespace detail {
template <class L> constexpr std::span<const length_spec> lengths_of() {
  if constexpr (requires { layer_info<L>::lengths; }) return layer_info<L>::lengths;
  else return {};
}
template <class L> constexpr std::span<const checksum_spec> checksums_of() {
  if constexpr (requires { layer_info<L>::checksums; }) return layer_info<L>::checksums;
  else return {};
}
template <class L> constexpr std::span<const std::string_view> selectors_of() {
  if constexpr (requires { layer_info<L>::selectors; }) return layer_info<L>::selectors;
  else return {};
}
template <class L> constexpr bool has_pseudo() { return requires { layer_info<L>::pseudo; }; }
template <class L> constexpr pseudo_spec pseudo_of() {
  if constexpr (has_pseudo<L>()) return layer_info<L>::pseudo;
  else return {};
}
/// Encode layer I of a (linked) stack into the header image at `off` (`total` = header image
/// size). Returns "" or why the layer cannot be templated.
template <std::size_t I, class... L>
constexpr std::string_view write_layer(const std::tuple<L...>& t, std::byte* img, std::size_t off, std::size_t total) {
  using T = std::tuple_element_t<I, std::tuple<L...>>;
  using W = wire_t<T>;
  constexpr std::size_t n = nanom::wire_size_v<W>;
  const T& l = std::get<I>(t);
  if constexpr (requires { layer_info<T>::check(l); }) {
    const std::string_view e = layer_info<T>::check(l);
    if (!e.empty()) return e;
  }
  if constexpr (std::is_same_v<W, T>) {
    auto r = nanom::emit(l, std::span<std::byte>(img + off, n), {}, std::endian::big);
    if (!r) return r.error().what;
  } else {
    if constexpr (requires { l.size(); })
      if (std::size_t(l.size()) != n)
        return "nanocraft: layer value is not fixed-size (IP / TCP options, someip{.tp}?): templates need fixed-size "
               "layers";
    nanowire::build_ctx c{};
    c.after = total - off - n;
    c.frame = img;
    if constexpr (I + 1 < sizeof...(L)) {
      using N = std::tuple_element_t<I + 1, std::tuple<L...>>;
      const N& nx = std::get<I + 1>(t);
      c.next_ethertype = next_ethertype(nx);
      c.next_ip_proto = next_ip_proto(nx);
      c.has_next_ip_proto = requires { nx.ip_protocol(); } || requires { layer_info<N>::ip_proto; };
    }
    bool ok;
    if constexpr (requires { layer_info<T>::write(l, img + off, c); }) ok = layer_info<T>::write(l, img + off, c);
    else if constexpr (requires { l.write(img + off, c); }) ok = l.write(img + off, c);
    else ok = l.write(img + off);
    if (!ok) return "nanocraft: a layer field value does not fit its wire field (the builder refused it)";
  }
  return {};
}
/// Run layer_info<A>::link(a, b) for every adjacent pair (fills next-protocol fields left at 0).
template <class... L>
constexpr void link_all(std::tuple<L...>& t) {
  [&]<std::size_t... I>(std::index_sequence<I...>) {
    (
        [&] {
          if constexpr (I + 1 < sizeof...(L)) {
            using A = std::tuple_element_t<I, std::tuple<L...>>;
            using B = std::tuple_element_t<I + 1, std::tuple<L...>>;
            if constexpr (requires(A& a, const B& b) { layer_info<A>::link(a, b); })
              layer_info<A>::link(std::get<I>(t), std::get<I + 1>(t));
          }
        }(),
        ...);
  }(std::index_sequence_for<L...>{});
}
}  // namespace detail

}  // namespace nanocraft

#endif  // NANOCRAFT_LAYER_HPP_INCLUDED
