// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_QUICHE_IP_ADDRESS_FAMILY_H_
#define QUICHE_COMMON_QUICHE_IP_ADDRESS_FAMILY_H_

#include <ostream>
#include "quiche/common/platform/api/quiche_export.h"

namespace quiche {

// IP address family type used in QUIC. This hides platform dependant IP address
// family types.
enum class IpAddressFamily {
  IP_V4,
  IP_V6,
  IP_UNSPEC,
};

QUICHE_EXPORT int ToPlatformAddressFamily(IpAddressFamily family);
QUICHE_EXPORT IpAddressFamily FromPlatformAddressFamily(int family);


// <--- INSERT THE STREAM OPERATOR HERE --->
inline std::ostream& operator<<(std::ostream& os,
                                const IpAddressFamily& address_family) {
  switch (address_family) {
    case IpAddressFamily::IP_V4:
      return os << "IP_V4";
    case IpAddressFamily::IP_V6:
      return os << "IP_V6";
    case IpAddressFamily::IP_UNSPEC:
      return os << "IP_UNSPEC";
  }
  // Fallback for unhandled values.
  return os << "Unknown IpAddressFamily (" << static_cast<int>(address_family)
            << ")";
}

}  // namespace quiche

#endif  // QUICHE_COMMON_QUICHE_IP_ADDRESS_FAMILY_H_
