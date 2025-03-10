// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.



#include "quiche/quic/core/frames/quic_spa_frame.h"

#include <ostream>

namespace quic
{
    QuicSpaFrame::QuicSpaFrame(QuicControlFrameId control_frame_id,
                               const QuicSocketAddress ipv4_address,
                               const QuicSocketAddress ipv6_address)
        : control_frame_id(control_frame_id),
          ipv4_address(ipv4_address),
          ipv6_address(ipv6_address) {}

    std::ostream& operator<<(std::ostream &os, const QuicSpaFrame &s) {
        os << "{ control_frame_id: " << s.control_frame_id 
        << ", ipv4_address: " << s.ipv4_address 
        << ", ipv6_address: " << s.ipv6_address << " }";
        return os;
    }

} // namespace quic

