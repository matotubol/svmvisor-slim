//! Cross-component offline test. The owner is a software device and the host
//! image is an immutable Rust allocation; no native effect or admission exists.
use svmvisor_hypervisor::{
    arch::x86_64::msr::{TARGET_PHYSICAL_BITS, TARGET_SIGNATURE},
    memory::{
        address::{AddressPolicy, EncryptionState},
        iommu::{
            host_walk,
            image::{HostPageTableImage, MappingRange, ProtectedRange, TablePage},
            tables::{HostDeviceEntry, PageCoherency, Permissions},
            virtualized::{
                compose::{self, GuestHostRange, HostMap},
                guest::DeviceEntry,
                snapshot::{Dependencies, Dependency, SnapshotPage, TrackedSnapshot, Writer},
            },
        },
    },
    svm::{
        configuration::{ConfigurationRoute, ScalarTarget},
        pci::{
            Bus, BusPolicy, ConfigOwner, Error, Function, FunctionSpec, Header, Interrupt, Region,
            Transition,
        },
    },
};

fn policy() -> AddressPolicy {
    AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

struct SoftwareDma<'a, 'b> {
    image: &'a HostPageTableImage<'b>,
    device: HostDeviceEntry,
    transfers: Vec<(u64, u64)>,
    transitions: usize,
}

impl ConfigOwner for SoftwareDma<'_, '_> {
    fn admit(&mut self, _: BusPolicy, _: &[Region], functions: &[Function]) -> Result<(), Error> {
        if functions.len() == 1 { Ok(()) } else { Err(Error::OwnerRejected) }
    }
    fn revalidate(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn apply(&mut self, _: Transition<'_>) -> Result<(), Error> {
        // No transfer can be in flight in this synchronous software device.
        self.transitions += 1;
        Ok(())
    }
    fn dma(&mut self, _: u16, address: u64, bytes: u64, write: bool) -> Result<(), Error> {
        if bytes == 0 || bytes > 4096 - (address & 4095) {
            return Err(Error::OwnerRejected);
        }
        let translated = host_walk::walk(policy(), self.device, address, |key| {
            self.image.read_word(key).ok_or(())
        })
        .map_err(|_| Error::OwnerRejected)?
        .ok_or(Error::OwnerRejected)?;
        if !(if write {
            translated.permissions.allows_write()
        } else {
            translated.permissions.allows_read()
        }) {
            return Err(Error::OwnerRejected);
        }
        self.transfers.push((address, translated.system_address));
        Ok(())
    }
    fn interrupt(&mut self, _: Interrupt, _: bool) -> Result<(), Error> {
        Err(Error::NoInterrupt)
    }
}

#[test]
fn pci_bme_gates_nonidentity_composed_dma_and_protected_aliases() {
    let mut guest_page = [0; 4096];
    // Windows-style nonidentity DVA -> GPA. The second output is protected;
    // the third aliases the guest translation table and must lose DMA write.
    for (index, gpa) in [(1usize, 0x8000u64), (2, 0x9000), (3, 0x10000)] {
        guest_page[index * 8..index * 8 + 8].copy_from_slice(&(gpa | 1 | (3 << 61)).to_le_bytes());
    }
    let pages = [SnapshotPage::copy(0x10000, 0x110000, &guest_page).unwrap()];
    let mut tracked = TrackedSnapshot::new(&pages).unwrap();
    let guest_device = DeviceEntry::decode([0x10000 | 3 | (1 << 9) | (3 << 61), 7, 1, 0]).unwrap();
    let host_ranges = [GuestHostRange {
        guest_base: 0,
        host_base: 0x100000,
        len: 0x20000,
        permissions: Permissions::ReadWrite,
    }];
    let protected = [ProtectedRange { base: 0x109000, len: 4096 }];
    let host = HostMap::new(policy(), &host_ranges, &protected).unwrap();
    let mut scratch = [MappingRange {
        io_base: 0,
        system_base: 0,
        len: 4096,
        permissions: Permissions::None,
        coherency: PageCoherency::Inherit,
    }; 16];
    let mut dependency_storage = [Dependency::EMPTY; 4];
    let mut dependencies = Dependencies::new(&mut dependency_storage);
    let composed = compose::compose(
        &tracked,
        guest_device,
        true,
        None,
        &host,
        &mut scratch,
        &mut dependencies,
    )
    .unwrap();
    let mut table_storage = vec![TablePage::ZERO; 4];
    let image =
        composed.build_image(policy(), 0x100000000, &mut table_storage, &protected).unwrap();
    let device =
        HostDeviceEntry::new(policy(), image.root_address(), 9, Permissions::ReadWrite).unwrap();
    let alias = host_walk::walk(policy(), device, 0x3000, |key| image.read_word(key).ok_or(()))
        .unwrap()
        .unwrap();
    assert_eq!(alias.system_address, 0x110000);
    assert!(alias.permissions.allows_read());
    assert!(!alias.permissions.allows_write());

    let route =
        ConfigurationRoute::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, 0xe000_0021)
            .unwrap();
    let bus_policy = BusPolicy {
        route,
        memory: Region { base: 0x80000000, bytes: 0x100000 },
        io: Region { base: 0x1000, bytes: 0x1000 },
    };
    let mut functions = [Function::new(FunctionSpec {
        bdf: 8,
        parent: None,
        vendor: 0x1234,
        device: 0x5678,
        class_code: 0x020000,
        revision: 1,
        multifunction: false,
        header: Header::Endpoint { subsystem_vendor: 0x1234, subsystem_device: 1 },
        bars: [None; 6],
        msi: false,
        interrupt_pin: 0,
    })
    .unwrap()];
    let mut owner = SoftwareDma { image: &image, device, transfers: vec![], transitions: 0 };
    {
        let mut bus = Bus::new(bus_policy, &[], &mut functions, &mut owner).unwrap();
        let command = ScalarTarget { bdf: 8, register: 4, width: 2 };
        assert_eq!(bus.dma(8, 0x1030, 16, true), Err(Error::BusMasterDisabled));
        bus.access(command, Some(4)).unwrap();
        bus.dma(8, 0x1030, 16, true).unwrap();
        bus.access(command, Some(0)).unwrap();
        assert_eq!(bus.dma(8, 0x1030, 16, true), Err(Error::BusMasterDisabled));
        bus.access(command, Some(4)).unwrap();
        assert_eq!(bus.dma(8, 0x2000, 16, true), Err(Error::OwnerRejected));
        // An uncertain effect error poisons the bus instead of permitting a
        // later successful continuation through the formerly valid mapping.
        assert!(bus.dma(8, 0x1030, 16, true).is_err());
    }
    assert_eq!(owner.transfers, [(0x1030, 0x108030)]);
    assert_eq!(owner.transitions, 3);
    assert!(tracked.observe_write(0x110000, 8, Writer::Cpu).unwrap());
    assert!(
        compose::compose(
            &tracked,
            guest_device,
            true,
            None,
            &host,
            &mut scratch,
            &mut dependencies
        )
        .is_err()
    );
}
