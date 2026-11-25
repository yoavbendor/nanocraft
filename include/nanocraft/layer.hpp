// SPDX-License-Identifier: Apache-2.0
// nanocraft/layer.hpp — the protocol seam: what the crafting engine needs to know about a layer.
//
// A layer is a fixed-size header struct registered with NANOM_DESCRIBE (its wire image is exactly
// what nanom::emit writes) plus a nanocraft::layer_info<L> specialization that tells the engine,
// declaratively, which of its fields are lengths, which are Internet checksums, and how it links to
// the layer stacked on top of it. The engine (frame_template.hpp) is protocol-independent: it only
// ever reads this table.
//
//   template <> struct nanocraft::layer_info<my_hdr> {
//     static constexpr std::string_view name = "my";                       // patch path prefix
//     static constexpr std::array lengths   = {length_spec{"len", 0, 0}};   // optional
//     static constexpr std::array checksums = {checksum_spec{"ck", checksum_kind::header}};  // optional
//     static constexpr pseudo_spec pseudo{...};                             // optional: an IP layer
//     static constexpr std::array selectors = {std::string_view{"type"}};  // optional: identity fields
//     template <class Next> static constexpr void link(my_hdr&, const Next&);  // optional
//   };
//
// Stacks are written with operator/ (`eth{} / ipv4{} / udp{}`) or nanocraft::stack{...}.
//
// nanowire (the protocol-definition library) will provide these specializations for its builders;
// until then nanocraft/detail/proto_stub.hpp provides a minimal set.
#ifndef NANOCRAFT_LAYER_HPP_INCLUDED
#define NANOCRAFT_LAYER_HPP_INCLUDED

#include <nanom/emit.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
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

template <class L>
concept layer = requires {
  { layer_info<L>::name } -> std::convertible_to<std::string_view>;
  requires nanom::Described<L>;
};

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
