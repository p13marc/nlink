# Watch DPLL lock-status transitions

Use the typed `Connection<Dpll>` API to enumerate the host's DPLL
hardware (SyncE / PTP / GNSS-disciplined clocks) and poll for
lock-status changes from telco-RAN, time-sync, or SmartNIC
control-plane code.

## When to use this

- You're writing a control plane that needs to react when a DPLL
  loses lock — failover to a different reference, alert oncall,
  switch to PTP only, etc.
- You're building observability around clock quality (Prometheus
  metrics, structured logs) and need the typed wire fields.
- You're a driver author cross-checking a new DPLL driver against
  the kernel UAPI without writing throwaway C.

If you just want to see what's on the host once, run the example —
`cargo run -p nlink --example genl_dpll -- show` — and read no
further.

## Kernel requirements

- **Linux 6.7+** for the family itself
  ([`include/uapi/linux/dpll.h`](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/dpll.h)).
- **Linux 6.10+** for `DPLL_A_LOCK_STATUS_ERROR` (reason a DPLL
  lost lock) and `DPLL_A_CLOCK_QUALITY_LEVEL` (ITU-T G.8264 quality
  level reporting).
- **Linux 6.11+** for `DPLL_A_PIN_MEASURED_FREQUENCY` +
  `DPLL_A_PIN_PHASE_ADJUST_GRAN`.
- **Linux 6.12+** for `DPLL_A_PHASE_OFFSET_MONITOR` +
  `DPLL_A_FREQUENCY_MONITOR` toggles.

All version-gated fields surface as `Option<…>` on
[`DpllDeviceReply`](../../crates/nlink/src/netlink/genl/dpll/messages.rs)
/ [`DpllPinReply`](../../crates/nlink/src/netlink/genl/dpll/messages.rs) —
the field is `None` on older kernels rather than producing a parse
error.

## Permissions

DPLL queries require **CAP_NET_ADMIN** on every recent kernel
(read-only included; per the in-kernel ACL at
`net/dpll/netlink.c`). Plan for either:

- Running your control plane as root, or
- Granting CAP_NET_ADMIN explicitly with
  `setcap cap_net_admin=ep /path/to/binary`.

`Error::is_permission_denied()` detects EPERM cleanly; the
example shows the idiomatic handling.

## High-level approach

1. Construct `Connection::<Dpll>::new_async().await?`. The family
   ID is resolved against the kernel at construction time;
   `Error::is_not_found()` if no DPLL driver is loaded.
2. **One-shot snapshot:** stream `conn.dump_devices()` and
   `conn.dump_pins()`. The streams return `Result<…>` per kernel
   frame (Plan 149 — O(1) memory).
3. **Polling loop:** repeat the snapshot on a tick (every 1-5 s
   is typical; the kernel doesn't push lock-state changes to a
   polling consumer — see "Multicast monitor" below for the
   push-based variant).
4. Compare the new snapshot's `device.lock_status` /
   `pin.state` / `pin.prio` against the previous snapshot to
   detect transitions.

## Code

```rust,no_run
use std::collections::HashMap;
use std::time::Duration;

use nlink::netlink::{
    genl::dpll::{Dpll, DpllDeviceReply, DpllLockStatus},
    Connection,
};
use tokio_stream::StreamExt;

# async fn run() -> nlink::Result<()> {
let conn = Connection::<Dpll>::new_async().await?;
let mut previous: HashMap<u32, DpllLockStatus> = HashMap::new();

loop {
    let mut stream = match conn.dump_devices().await {
        Ok(s) => s,
        Err(e) if e.is_permission_denied() => {
            tracing::error!("DPLL queries need CAP_NET_ADMIN");
            return Err(e);
        }
        Err(e) => return Err(e),
    };

    let mut current: HashMap<u32, DpllLockStatus> = HashMap::new();
    while let Some(dev) = stream.next().await {
        let dev: DpllDeviceReply = dev?;
        if let Some(status) = dev.lock_status {
            current.insert(dev.id, status);

            if let Some(prev) = previous.get(&dev.id) {
                if *prev != status {
                    tracing::info!(
                        device = dev.id,
                        from = ?prev,
                        to = ?status,
                        module = %dev.module_name,
                        "lock status changed",
                    );
                    // Fan out to a failover handler, metric counter,
                    // or alert pipeline as appropriate.
                    on_lock_status_change(dev.id, *prev, status, &dev);
                }
            } else {
                tracing::info!(
                    device = dev.id,
                    status = ?status,
                    "device discovered",
                );
            }
        }
    }

    // Devices that disappeared since the last sweep.
    for (id, _) in previous.iter().filter(|(id, _)| !current.contains_key(id)) {
        tracing::info!(device = id, "device removed");
    }

    previous = current;
    tokio::time::sleep(Duration::from_secs(2)).await;
}
# }
# fn on_lock_status_change(
#     _id: u32,
#     _from: DpllLockStatus,
#     _to: DpllLockStatus,
#     _dev: &DpllDeviceReply,
# ) {}
```

## Holdover detection

The `Locked` ↔ `LockedHoAcq` transition is the "we just acquired
holdover capability" event — the device can now survive reference
loss without frequency drift beyond holdover spec. Pair this with
your failover policy:

```rust,no_run
use nlink::netlink::genl::dpll::DpllLockStatus;
# fn handle(from: DpllLockStatus, to: DpllLockStatus) {
match (from, to) {
    (DpllLockStatus::Locked, DpllLockStatus::LockedHoAcq) => {
        // Safe to schedule maintenance — holdover acquired.
    }
    (DpllLockStatus::LockedHoAcq, DpllLockStatus::Holdover) => {
        // Reference lost; running on holdover. Start the failover
        // countdown — most ITU-T G.8262 profiles allow ~24h
        // before phase drift exceeds the network's PTP budget.
    }
    (_, DpllLockStatus::Unlocked) => {
        // Hard lock loss. Alert oncall immediately.
    }
    _ => {}
}
# }
```

## Lock-loss diagnostics

When a device transitions to `Unlocked`, `DpllDeviceReply::lock_status_error`
carries the kernel's reason (kernel 6.10+):

```rust,no_run
use nlink::netlink::genl::dpll::{DpllDeviceReply, DpllLockStatusError};
# fn explain(dev: &DpllDeviceReply) {
match dev.lock_status_error {
    Some(DpllLockStatusError::None) => {
        // No error; device is fine.
    }
    Some(DpllLockStatusError::MediaDown) => {
        // The source link is physically down. Check `ip link show`
        // for the underlying NIC.
    }
    Some(DpllLockStatusError::FractionalFrequencyOffsetTooHigh) => {
        // Reference clock is drifting outside spec. Reference is
        // bad, not the DPLL.
    }
    Some(DpllLockStatusError::Undefined) | None => {
        // Either a kernel <6.10 or the driver doesn't report.
    }
    _ => {}
}
# }
```

## Pin selection (advanced)

When a DPLL is in `Automatic` mode and loses its primary
reference, the kernel auto-selects the highest-priority `Selectable`
pin. To watch which pin won (or to nudge selection by tweaking
priorities), iterate over pins after each device change:

```rust,no_run
use nlink::netlink::{
    genl::dpll::{Dpll, DpllPinState},
    Connection,
};
use tokio_stream::StreamExt;

# async fn run(conn: &Connection<Dpll>, device_id: u32) -> nlink::Result<()> {
let mut pins = conn.dump_pins().await?;
while let Some(pin) = pins.next().await {
    let pin = pin?;
    let parent = pin.parent_device.as_ref().map(|p| p.parent_id);
    if parent != Some(device_id) {
        continue;
    }
    if pin.state == Some(DpllPinState::Connected) {
        tracing::info!(
            pin = pin.id,
            label = ?pin.board_label,
            prio = ?pin.prio,
            "device {device_id}: active reference",
        );
    }
}
# Ok(())
# }
```

To force a specific pin (operator override), set its priority
to 0 — lower wins:

```rust,no_run
use nlink::netlink::{genl::dpll::Dpll, Connection};
# async fn run(conn: &Connection<Dpll>, pin_id: u32) -> nlink::Result<()> {
conn.set_pin_priority(pin_id, 0).await?;
# Ok(())
# }
```

`Error::is_invalid_argument()` if the pin's capabilities don't
include `DpllPinCapabilities::PRIORITY_CAN_CHANGE` — check the
pin's `capabilities` field before attempting.

## Multicast monitor (push-based — preferred)

The kernel emits **`DPLL_CMD_*_CHANGE_NTF` notifications** on the
`monitor` multicast group whenever a device or pin is created,
deleted, or changes state. Subscribing gives sub-millisecond
latency on lock changes — preferred over the polling loop above
for control planes that need to react quickly.

```rust,no_run
use nlink::netlink::{
    genl::dpll::{Dpll, DpllEvent},
    Connection,
};
use tokio_stream::StreamExt;

# async fn run() -> nlink::Result<()> {
let mut conn = Connection::<Dpll>::new_async().await?;
conn.subscribe_monitor()?;       // resolves "monitor" group via the macro stack
let mut events = conn.events();

while let Some(evt) = events.next().await {
    match evt? {
        DpllEvent::DeviceChanged(dev) => {
            tracing::info!(
                device = dev.id,
                lock = ?dev.lock_status,
                "device state change",
            );
        }
        DpllEvent::PinChanged(pin) => {
            tracing::info!(
                pin = pin.id,
                state = ?pin.state,
                "pin state change",
            );
        }
        DpllEvent::DeviceDeleted { id } => {
            tracing::warn!(device = id, "DPLL device removed");
        }
        DpllEvent::PinDeleted { id } => {
            tracing::warn!(pin = id, "DPLL pin removed");
        }
        DpllEvent::DeviceCreated(dev) => {
            tracing::info!(device = dev.id, "DPLL device appeared");
        }
        DpllEvent::PinCreated(pin) => {
            tracing::info!(pin = pin.id, "DPLL pin appeared");
        }
    }
}
# Ok(())
# }
```

`subscribe_monitor()` returns
`Error::FamilyNotFound { name: "dpll::monitor" }` if the kernel
doesn't register the group (kernel too old, or DPLL driver
doesn't expose monitor). Fall back to the polling loop above in
that case.

The polling loop is still valuable for cross-kernel-version
compatibility (works on any kernel that has CONFIG_DPLL) — pick
push for latency, polling for portability.

## See also

- [`crates/nlink/examples/genl/dpll.rs`](../../crates/nlink/examples/genl/dpll.rs)
  — runnable end-to-end version of the snapshot step in this
  recipe.
- [`docs/recipes/define-your-own-genl-family.md`](define-your-own-genl-family.md)
  — DPLL is the canonical in-tree dogfood of the macro stack; the
  recipe walks through how the family is declared.
- Plan 156 ([`plans/156-0.16-dpll-genl-family-plan.md`](../../plans/156-0.16-dpll-genl-family-plan.md))
  — design rationale + per-phase status.
- Kernel docs: `Documentation/driver-api/dpll.rst` (kernel 6.7+).
- ITU-T G.8264 §11-7 — clock quality level definitions referenced
  by `DpllClockQualityLevel`.
