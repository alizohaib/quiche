// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is responsible for the masque_server binary. It allows testing
// our MASQUE server code by creating a MASQUE proxy that relays HTTP/3
// requests to web servers tunnelled over MASQUE connections.
// e.g.: masque_server

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <random>

#include "quiche/quic/masque/masque_server.h"
#include "quiche/quic/masque/masque_server_backend.h"
#include "quiche/quic/masque/masque_utils.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, port, 9661,
                                "The port the MASQUE server will listen on.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, cache_dir, "",
    "Specifies the directory used during QuicHttpResponseCache "
    "construction to seed the cache. Cache directory can be "
    "generated using `wget -p --save-headers <url>`");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, server_authority, "",
    "Specifies the authority over which the server will accept MASQUE "
    "requests. Defaults to empty which allows all authorities.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, masque_mode, "",
    "Allows setting MASQUE mode, currently only valid value is \"open\".");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, concealed_auth, "",
    "Require HTTP Concealed Authentication. Pass in a list of key identifiers "
    "and hex-encoded public keys. "
    "Separated with colons and semicolons. "
    "For example: \"kid1:0123...f;kid2:0123...f\".");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, concealed_auth_on_all_requests, false,
    "If set to true, enable concealed auth on all requests (such as GET) "
    "instead of just MASQUE.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, preferred_addr, "2600:3c01:e000:8e0::0",
    "Preferred Address to send to client as Transport Parameter ");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, server_ipv6_hopping, true,
    "If enabled, custom SPA frames will be sent to the client every n packets");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int, send_spa_frames_every_n_packets, 50,
    "Send custom SPA frames every N packets. Defaults to 100.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int, preferred_addr_prefix, 124,
    "Server's IPv6 Preferred Address Prefix");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, enable_wf_defense, false,
    "If enabled, FRONT WF defense will be enabled on all connections.");

int main(int argc, char* argv[]) {
  const char* usage = "Usage: masque_server [options]";
  std::vector<std::string> non_option_args =
      quiche::QuicheParseCommandLineFlags(usage, argc, argv);
  if (!non_option_args.empty()) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 0;
  }

  quiche::QuicheSystemEventLoop event_loop("masque_server");
  quic::MasqueMode masque_mode = quic::MasqueMode::kOpen;
  std::string mode_string = quiche::GetQuicheCommandLineFlag(FLAGS_masque_mode);
  if (!mode_string.empty() && mode_string != "open") {
    QUIC_LOG(ERROR) << "Invalid masque_mode \"" << mode_string << "\"";
    return 1;
  }

  auto backend = std::make_unique<quic::MasqueServerBackend>(
      masque_mode, quiche::GetQuicheCommandLineFlag(FLAGS_server_authority),
      quiche::GetQuicheCommandLineFlag(FLAGS_cache_dir));

  backend->SetConcealedAuth(
      quiche::GetQuicheCommandLineFlag(FLAGS_concealed_auth));
  backend->SetConcealedAuthOnAllRequests(
      quiche::GetQuicheCommandLineFlag(FLAGS_concealed_auth_on_all_requests));

  auto config = quic::QuicConfig();
  quic::QuicIpAddress host;
  host.FromString(quiche::GetQuicheCommandLineFlag(FLAGS_preferred_addr));
  quic::QuicSocketAddress kTestServerAddress = quic::QuicSocketAddress(host, quiche::GetQuicheCommandLineFlag(FLAGS_port));
  config.SetIPv6AlternateServerAddressToSend(kTestServerAddress);

//   For IPv4 Preferred Address
//   quic::QuicIpAddress host2;
//   host2.FromString("45.33.41.5");
//   quic::QuicSocketAddress kTestv4ServerAddress = quic::QuicSocketAddress(host2, FLAGS_port);
//   config.SetIPv4AlternateServerAddressToSend(kTestv4ServerAddress);

  config.SetDefenseEnabled(quiche::GetQuicheCommandLineFlag(FLAGS_enable_wf_defense));

  // On the server side, server hopping is enabled by default
  config.SetServerIpv6Hopping(quiche::GetQuicheCommandLineFlag(FLAGS_server_ipv6_hopping));

  // Send SPA frames every n packets
  config.SetMigrateEveryNPackets(quiche::GetQuicheCommandLineFlag(FLAGS_send_spa_frames_every_n_packets));

  // Set the prefix for the server hopping. A random address will be sent from this prefix
  // to the client in the SPA frame (different from the transport parameter preferred address)
  config.SetServerHoppingPrefix(quiche::GetQuicheCommandLineFlag(FLAGS_preferred_addr_prefix));

  // Initialize random number generators
  std::random_device rd;
  std::mt19937 gen(rd());

  // Set FRONT Parameters for the Server connection. Taken from the FRONT paper.
  double w_min = 0.2;
  double w_max = 3;
  double n = 1000;

  // Uniform distribution for generating window sizes
  std::uniform_real_distribution<> uniform_dist(w_min, w_max);
  double wnd_server = uniform_dist(gen);

  std::uniform_int_distribution<> server_dist(1, n);
  int server_dummy_num = server_dist(gen);

  config.SetFrontWnd(wnd_server);
  config.SetFrontSamples(server_dummy_num);

  auto server =
      std::make_unique<quic::MasqueServer>(masque_mode, backend.get(), config);

  if (!server->CreateUDPSocketAndListen(quic::QuicSocketAddress(
          quic::QuicIpAddress::Any6(),
          quiche::GetQuicheCommandLineFlag(FLAGS_port)))) {
    return 1;
  }

  QUIC_LOG(INFO) << "Started " << masque_mode << " MASQUE server";
  server->HandleEventsForever();
  return 0;
}
