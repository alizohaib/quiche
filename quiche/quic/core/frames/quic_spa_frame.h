// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_FRAMES_QUIC_SPA_FRAME_H_
#define QUICHE_QUIC_CORE_FRAMES_QUIC_SPA_FRAME_H_

#include <ostream>

#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quic
{
    struct QUICHE_EXPORT QuicSpaFrame
    {
        QuicSpaFrame() = default;
        QuicSpaFrame(QuicControlFrameId control_frame_id,
                     const QuicSocketAddress ipv4_address,
                     const QuicSocketAddress ipv6_address);

            friend QUICHE_EXPORT std::ostream &
            operator<<(std::ostream &os,
                       const QuicSpaFrame &frame);

        // A unique identifier of this control frame. 0 when this frame is received,
        // and non-zero when sent.
        QuicControlFrameId control_frame_id = kInvalidControlFrameId;
        QuicSocketAddress ipv4_address;
        QuicSocketAddress ipv6_address;
        
    };

} // namespace quic

#endif // QUICHE_QUIC_CORE_FRAMES_QUIC_SPA_FRAME_H_
