// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

// Allow naming conventions from auto-generated C headers
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
// The bindgen output's zero-length-array placeholder carries unsafe
// accessor helpers without safety docs. The generated code is
// bindgen-owned, so the lint is suppressed at the module level.
#![allow(clippy::missing_safety_doc)]

include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
