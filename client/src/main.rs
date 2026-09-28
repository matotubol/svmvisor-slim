
//! ```text
//! cargo run -p svmvisor-client -- --size 2560x1440
//! cargo run -p svmvisor-client -- --verbose
//! ```
//!
//! # Offsets
//!
//! Everything build-specific in this file is a `const` in [`offsets`] or [`schema`]. All ten of
//! them were verified together against `cs2-dumper` build **14185**; the build number is in the
//! dump's `info.json`. After a game update, re-dump and re-check *all* of them: a stale module
//! pointer and a stale field offset both fail the same silent way, as zero players and no error.
//! Use `--verbose` to see which step of the walk actually failed.


use std::{env, error::Error, process::ExitCode, thread, time::Duration};

use svmvisor_client::{ErrorKind, Module, Process};

mod overlay;

/// `client.dll` data addresses the drawing reads, each relative to the image base. What no offset
/// does is read a field: those are in [`schema`].
mod offsets {
    // Build 14185. These move every game update, and a stale one fails silently: re-dump and
    // re-check every offset here together.
    pub mod entity_system {
        pub const BASE: u64 = 0x0271_51a8;
    }

    pub mod local_player {
        pub const PAWN: u64 = 0x0256_06d8;
    }

    pub mod render {
        pub const VIEW_MATRIX: u64 = 0x0256_5a20;
    }
}

/// Fields reached by pointer, by the names the schema gives them.
mod schema {
    // C_BaseEntity, and the scene node the skeleton hangs off.
    pub const SCENE_NODE: u64 = 0x330;
    pub const HEALTH: u64 = 0x34c;
    pub const LIFE_STATE: u64 = 0x354;
    pub const TEAM: u64 = 0x3e7;

    // CGameSceneNode.
    pub const ABS_ORIGIN: u64 = 0xc8;

    // CSkeletonInstance::m_modelState, and the bone array pointer inside that CModelState. The
    // pointer is not a schematized field: `m_hModel` at `0xa0` is the first that is, so `0x80` into
    // it is the community value.
    pub const BONE_ARRAY: u64 = 0x140 + 0x80;

    // CBasePlayerController::m_hPawn, the handle from a controller to its pawn.
    pub const PAWN_HANDLE: u64 = 0x6bc;

    // The entity list. Its chunks hang off `CGameEntitySystem + 0x10`, eight bytes per chunk, and
    // each chunk is 512 entity slots of `SLOT_STRIDE` bytes rather than of pointers.
    pub const ENTITY_CHUNK: u64 = 0x10;
    pub const SLOT_STRIDE: u64 = 0x70;
    pub const SLOT_SHIFT: u32 = 9;
    pub const SLOT_MASK: u32 = 0x1ff;
    pub const HANDLE_MASK: u32 = 0x7fff;
}

/// The game's own bone indices, as a player's skeleton numbers them.
mod joint {
    pub const ORIGIN: usize = 0;
    pub const PELVIS: usize = 1;
    pub const SPINE_1: usize = 3;
    pub const SPINE_2: usize = 4;
    pub const NECK: usize = 6;
    pub const HEAD: usize = 7;
    pub const SHOULDER_L: usize = 9;
    pub const ELBOW_L: usize = 10;
    pub const HAND_L: usize = 11;
    pub const SHOULDER_R: usize = 13;
    pub const ELBOW_R: usize = 14;
    pub const HAND_R: usize = 15;
    pub const HIP_L: usize = 17;
    pub const KNEE_L: usize = 18;
    pub const FOOT_L: usize = 19;
    pub const HIP_R: usize = 20;
    pub const KNEE_R: usize = 21;
    pub const FOOT_R: usize = 22;
    pub const CHEST: usize = 23;
}

/// The lines drawn between those joints: the spine, both arms and both legs.
const CONNECTIONS: [(usize, usize); 17] = [
    (joint::PELVIS, joint::SPINE_1),
    (joint::SPINE_1, joint::SPINE_2),
    (joint::SPINE_2, joint::CHEST),
    (joint::CHEST, joint::NECK),
    (joint::NECK, joint::HEAD),
    (joint::NECK, joint::SHOULDER_L),
    (joint::SHOULDER_L, joint::ELBOW_L),
    (joint::ELBOW_L, joint::HAND_L),
    (joint::NECK, joint::SHOULDER_R),
    (joint::SHOULDER_R, joint::ELBOW_R),
    (joint::ELBOW_R, joint::HAND_R),
    (joint::PELVIS, joint::HIP_L),
    (joint::HIP_L, joint::KNEE_L),
    (joint::KNEE_L, joint::FOOT_L),
    (joint::PELVIS, joint::HIP_R),
    (joint::HIP_R, joint::KNEE_R),
    (joint::KNEE_R, joint::FOOT_R),
];

/// Bone entries: 32 bytes each with the position in the first 12, and 30 of them cover every joint.
const BONE_STRIDE: usize = 32;
const BONE_COUNT: usize = 30;
const BONE_POSITION: usize = 0x00;

/// Where a player's slots start in the entity list and how many there are. Players are controllers,
/// which the game keeps in the first slots.
const FIRST_SLOT: u32 = 1;
const PLAYER_SLOTS: u32 = 64;

/// How far the root joint may sit from the entity's own origin, and how far the head may stand
/// above that root for a skeleton to count as a person. The game's own fallback uses 65 units when a
/// model has no bones at all, so anything in this band is a standing figure.
const ROOT_TOLERANCE: f32 = 100.0;
const MIN_HEIGHT: f32 = 45.0;
const MAX_HEIGHT: f32 = 100.0;

/// Screen the matrix is projected into when no `--size` is given, and the text overlay's shape.
const DEFAULT_WIDTH: f32 = 1920.0;
const DEFAULT_HEIGHT: f32 = 1080.0;
const GRID_COLUMNS: usize = 96;
const GRID_ROWS: usize = 27;
const LINE_STEPS: u32 = 40;

/// A clip `w` below this is on the eye or behind the lens, so there is no pixel for it.
const NEAR_CLIP: f32 = 0.1;

/// Wait between overlay frames. Each one costs a few reads per player, not per entity.
const FRAME_MILLIS: u64 = 16;

const USAGE: &str = "
  --size <WxH>        screen the matrix is projected into (default 1920x1080)
  --transpose         transpose the matrix first, for a client.dll that stores it column-major
  --verbose           show every step of the entity walk and why each slot was rejected";

type Vec3 = [f32; 3];

/// A 4x4 row-major world-to-clip matrix, in the layout `client.dll` holds it.
type Mat4 = [[f32; 4]; 4];

/// One skeleton's bone entries, exactly as read.
type BoneEntries = [[u8; BONE_STRIDE]; BONE_COUNT];

/// One enemy worth drawing, with the bones read for it.
struct Player {
    slot: u32,
    pawn: u64,
    bones: BoneEntries,
}

/// The enemies found, and how many pawns looked alive but had no skeleton shaped like a person.
struct Found {
    players: Vec<Player>,
    boneless: usize,
}

/// Everything the command line asked for.
struct Options {
    width: f32,
    height: f32,
    transpose: bool,
    verbose: bool,
}

impl Options {
    /// The options in `arguments`, `None` once usage has been printed, or what is wrong with them.
    fn parse(arguments: Vec<String>) -> Result<Option<Self>, String> {
        let mut options = Self {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            transpose: false,
            verbose: false,
        };
        let mut index = 0;
        while index < arguments.len() {
            let argument = arguments[index].clone();
            index += 1;
            match argument.as_str() {
                "--help" | "-h" => {
                    println!("Usage: svmvisor-client [options]{USAGE}");
                    return Ok(None);
                }
                "--transpose" => options.transpose = true,
                "--verbose" => options.verbose = true,
                "--size" => {
                    let (width, height) = size(&value(&arguments, &mut index, &argument)?)?;
                    (options.width, options.height) = (width, height);
                }
                _ => {
                    return Err(format!(
                        "Unknown option {argument}.\nUsage: svmvisor-client [options]{USAGE}"
                    ));
                }
            }
        }
        Ok(Some(options))
    }
}

// Small helpers.

fn sub(a: Vec3, b: Vec3) -> Vec3 {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}

fn dot(a: Vec3, b: Vec3) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn length(v: Vec3) -> f32 {
    dot(v, v).sqrt()
}

/// Eight little-endian bytes as one number.
fn read_u64(bytes: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(raw)
}

/// True when `value` could be an address in the process, which a stray field usually is not.
fn is_pointer(value: u64) -> bool {
    (0x1_0000..0x0000_8000_0000_0000).contains(&value)
}

/// 3D world coordinates to 2D screen pixels, or `None` behind the lens.
fn world_to_screen(view_projection: &Mat4, p: Vec3, width: f32, height: f32) -> Option<(f32, f32)> {
    let w = view_projection[3][0] * p[0]
        + view_projection[3][1] * p[1]
        + view_projection[3][2] * p[2]
        + view_projection[3][3];
    if w < NEAR_CLIP {
        return None;
    }
    let clip_x = view_projection[0][0] * p[0]
        + view_projection[0][1] * p[1]
        + view_projection[0][2] * p[2]
        + view_projection[0][3];
    let clip_y = view_projection[1][0] * p[0]
        + view_projection[1][1] * p[1]
        + view_projection[1][2] * p[2]
        + view_projection[1][3];
    Some(((width * 0.5) * (1.0 + clip_x / w), (height * 0.5) * (1.0 - clip_y / w)))
}

fn transpose(matrix: &Mat4) -> Mat4 {
    let mut out = [[0.0; 4]; 4];
    for (row, values) in out.iter_mut().enumerate() {
        for (column, value) in values.iter_mut().enumerate() {
            *value = matrix[column][row];
        }
    }
    out
}

/// True when the matrix's first two rows are perpendicular and non-zero, which a world-to-clip
/// matrix's are. A matrix of zeros, read before a map loads, is not one.
fn is_world_to_clip(view_projection: &Mat4) -> bool {
    let row = |row: [f32; 4]| {
        let length = length([row[0], row[1], row[2]]);
        if length < 1e-6 { [0.0; 3] } else { [row[0] / length, row[1] / length, row[2] / length] }
    };
    let (right, up) = (row(view_projection[0]), row(view_projection[1]));
    length(right) > 0.5 && length(up) > 0.5 && dot(right, up).abs() <= 0.01
}

// The walk.

/// The enemies to draw, each with the bones read for it.
///
/// A player slot holds a controller, and the controller's `m_hPawn` handle names the pawn every
/// other field lives on. One read covers all 64 controller slots, because the slots are `0x70`
/// bytes apart and contiguous.
fn players(process: &mut Process, client: &Module) -> svmvisor_client::Result<Found> {
    let mut found = Found { players: Vec::new(), boneless: 0 };
    let local_pawn: u64 = process.read_module(client, offsets::local_player::PAWN)?;
    let local_team = match local_pawn {
        0 => None,
        pawn => Some(process.read::<u8>(pawn + schema::TEAM)?),
    };
    let list: u64 = process.read_module(client, offsets::entity_system::BASE)?;
    if !is_pointer(list) {
        return Ok(found);
    }
    let chunk: u64 = process.read(list + schema::ENTITY_CHUNK)?;
    if !is_pointer(chunk) {
        return Ok(found);
    }
    let mut slots = vec![0u8; PLAYER_SLOTS as usize * schema::SLOT_STRIDE as usize];
    process.read_into(chunk + FIRST_SLOT as u64 * schema::SLOT_STRIDE, &mut slots)?;

    for slot in FIRST_SLOT..=PLAYER_SLOTS {
        let controller =
            read_u64(&slots, (slot - FIRST_SLOT) as usize * schema::SLOT_STRIDE as usize);
        if !is_pointer(controller) {
            continue;
        }
        let Ok(handle) = process.read::<u32>(controller + schema::PAWN_HANDLE) else { continue };
        if handle == 0 || handle == u32::MAX {
            continue;
        }
        let Ok(pawn) = pawn_of(process, list, handle) else { continue };
        if !is_pointer(pawn) || pawn == local_pawn {
            continue;
        }
        let Ok(health) = process.read::<i32>(pawn + schema::HEALTH) else { continue };
        let Ok(life) = process.read::<u8>(pawn + schema::LIFE_STATE) else { continue };
        let Ok(team) = process.read::<u8>(pawn + schema::TEAM) else { continue };
        // Health, no death state and one of the two team numbers are what a living player has.
        if !(1..=100).contains(&health) || life != 0 || local_team == Some(team) {
            continue;
        }
        match skeleton(process, pawn) {
            Ok(Some((bones, origin))) if looks_like_a_player(&bones, origin) => {
                found.players.push(Player { slot, pawn, bones });
            }
            Ok(_) => found.boneless += 1,
            Err(error) if is_fatal(error.kind()) => return Err(error),
            Err(_) => found.boneless += 1,
        }
    }
    Ok(found)
}

/// The pawn the handle in a controller names: the handle holds an entity index, which the same
/// chunked list resolves, one chunk of 512 slots per index bit above nine.
fn pawn_of(process: &mut Process, list: u64, handle: u32) -> svmvisor_client::Result<u64> {
    let index = handle & schema::HANDLE_MASK;
    let chunk: u64 =
        process.read(list + schema::ENTITY_CHUNK + 8 * u64::from(index >> schema::SLOT_SHIFT))?;
    if !is_pointer(chunk) {
        return Ok(0);
    }
    process.read(chunk + schema::SLOT_STRIDE * u64::from(index & schema::SLOT_MASK))
}

/// The bone entries of `pawn`'s skeleton and the origin they should stand at, or `None` when the
/// scene node holds no bone array.
fn skeleton(
    process: &mut Process,
    pawn: u64,
) -> svmvisor_client::Result<Option<(BoneEntries, Vec3)>> {
    let scene_node: u64 = process.read(pawn + schema::SCENE_NODE)?;
    if !is_pointer(scene_node) {
        return Ok(None);
    }
    let array: u64 = process.read(scene_node + schema::BONE_ARRAY)?;
    if !is_pointer(array) {
        return Ok(None);
    }
    let bones: BoneEntries = process.read(array)?;
    let origin: Vec3 = process.read(scene_node + schema::ABS_ORIGIN)?;
    Ok(Some((bones, origin)))
}

/// Three little-endian floats at the position field of one bone entry.
fn bone(entries: &BoneEntries, index: usize) -> Vec3 {
    let entry = &entries[index];
    let at = |axis: usize| {
        let at = BONE_POSITION + axis * 4;
        f32::from_le_bytes([entry[at], entry[at + 1], entry[at + 2], entry[at + 3]])
    };
    [at(0), at(1), at(2)]
}

/// True when `entries` is shaped like a standing person measured from `origin`: the root joint at
/// the feet, and the head about a player's height above it.
fn looks_like_a_player(entries: &BoneEntries, origin: Vec3) -> bool {
    let root = bone(entries, joint::ORIGIN);
    let height = bone(entries, joint::HEAD)[2] - root[2];
    length(sub(root, origin)) < ROOT_TOLERANCE && (MIN_HEIGHT..=MAX_HEIGHT).contains(&height)
}

// The overlay.

/// The bone lines of every player, in screen pixels.
struct Frame {
    lines: Vec<((f32, f32), (f32, f32))>,
}

impl Frame {
    /// Projects each player's connections, leaving out a bone behind the lens and its lines.
    fn new(players: &[Player], view_projection: &Mat4, options: &Options) -> Self {
        let mut lines = Vec::new();
        for player in players {
            let pixel = |index: usize| {
                world_to_screen(
                    view_projection,
                    bone(&player.bones, index),
                    options.width,
                    options.height,
                )
            };
            for (from, to) in CONNECTIONS {
                if let (Some(from), Some(to)) = (pixel(from), pixel(to)) {
                    lines.push((from, to));
                }
            }
        }
        Self { lines }
    }
}

/// A text overlay of the same lines, for a run that wants something written down. Coordinates are
/// screen fractions, so it needs no viewport of its own.
struct Canvas {
    cells: Vec<Vec<char>>,
}

impl Canvas {
    fn new() -> Self {
        Self { cells: vec![vec![' '; GRID_COLUMNS]; GRID_ROWS] }
    }

    /// Writes `ch` at a screen fraction.
    fn plot(&mut self, x: f32, y: f32, ch: char) {
        let column = (x * GRID_COLUMNS as f32) as isize;
        let row = (y * GRID_ROWS as f32) as isize;
        if column >= 0 && row >= 0 && (column as usize) < GRID_COLUMNS && (row as usize) < GRID_ROWS
        {
            self.cells[row as usize][column as usize] = ch;
        }
    }

    /// Draws a line between two screen fractions.
    fn line(&mut self, a: (f32, f32), b: (f32, f32)) {
        for step in 0..=LINE_STEPS {
            let t = step as f32 / LINE_STEPS as f32;
            self.plot(a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t, '.');
        }
    }

    /// The frame as framed lines of text.
    fn render(&self) -> String {
        let rule = format!("+{}+\n", "-".repeat(GRID_COLUMNS));
        let mut text = rule.clone();
        for row in &self.cells {
            text += &format!("|{}|\n", row.iter().collect::<String>());
        }
        text += &rule;
        text
    }
}

// The run.

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let Some(options) = Options::parse(env::args().skip(1).collect())? else {
        return Ok(());
    };
    let Some(mut process) = svmvisor_client::pick(svmvisor_client::config())? else {
        return Ok(());
    };
    let client =
        process.module("client.dll")?.ok_or("client.dll is not loaded in the picked process.")?;
    println!("Attached to {} (pid {}).", process.name(), process.pid());
    println!("client.dll at 0x{:016x}, 0x{:x} bytes.", client.base, client.size);

    let view_projection = read_matrix(&mut process, &client, &options)?;
    log(&mut process, &client, &view_projection, &options);

    println!(
        "\nOverlay over {:.0}x{:.0} at the top-left of the primary monitor; \
         close the window or press Ctrl+C to stop.",
        options.width, options.height
    );
    let Some(mut window) = overlay::Overlay::open(options.width as u32, options.height as u32)
    else {
        return Err("Windows refused the overlay window.".into());
    };
    loop {
        if !window.pump() {
            return Ok(());
        }
        let Ok(view_projection) = read_matrix(&mut process, &client, &options) else {
            thread::sleep(Duration::from_millis(FRAME_MILLIS));
            continue;
        };
        match players(&mut process, &client) {
            Ok(found) => {
                let frame = Frame::new(&found.players, &view_projection, &options);
                window.draw(&frame.lines);
            }
            // A process that exited or a session that ended cannot be outlived; anything else is
            // one bad frame.
            Err(error) if is_fatal(error.kind()) => return Err(error.into()),
            Err(error) => eprintln!("  {error}"),
        }
        thread::sleep(Duration::from_millis(FRAME_MILLIS));
    }
}

/// The view matrix now, transposed first when the options say so.
fn read_matrix(
    process: &mut Process,
    client: &Module,
    options: &Options,
) -> svmvisor_client::Result<Mat4> {
    let view_projection: Mat4 = process.read_module(client, offsets::render::VIEW_MATRIX)?;
    Ok(if options.transpose { transpose(&view_projection) } else { view_projection })
}

/// True for failures that close the process or the session, which the overlay cannot outlive.
fn is_fatal(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::ProcessGone | ErrorKind::InvalidHandle | ErrorKind::SessionEnded)
}

/// Every step of the entity walk, written out, so a wrong offset can be told apart from an empty
/// server. Each line states what was read and which check rejected it; nothing here is silent.
fn diagnose(process: &mut Process, client: &Module) {
    println!("\n-- entity walk --");
    let local_pawn: u64 = match process.read_module(client, offsets::local_player::PAWN) {
        Ok(value) => value,
        Err(error) => {
            println!("local pawn at +0x{:x}: unreadable ({error})", offsets::local_player::PAWN);
            return;
        }
    };
    println!("local pawn at +0x{:x} = 0x{local_pawn:x}", offsets::local_player::PAWN);
    if !is_pointer(local_pawn) {
        println!("  not a pointer: LOCAL_PLAYER::PAWN is wrong, or you are not in a match");
    } else {
        match process.read::<u8>(local_pawn + schema::TEAM) {
            Ok(team) => println!("  local team at +0x{:x} = {team}", schema::TEAM),
            Err(error) => println!("  local team unreadable ({error}): TEAM is wrong"),
        }
    }

    let list: u64 = match process.read_module(client, offsets::entity_system::BASE) {
        Ok(value) => value,
        Err(error) => {
            println!("entity list at +0x{:x}: unreadable ({error})", offsets::entity_system::BASE);
            return;
        }
    };
    println!("entity list at +0x{:x} = 0x{list:x}", offsets::entity_system::BASE);
    if !is_pointer(list) {
        println!("  not a pointer: ENTITY_SYSTEM::BASE is wrong");
        return;
    }

    let Some(chunk) = process.read::<u64>(list + schema::ENTITY_CHUNK).ok() else {
        println!("  chunk pointer unreadable: ENTITY_CHUNK is wrong");
        return;
    };
    println!("  chunk at +0x{:x} = 0x{chunk:x}", schema::ENTITY_CHUNK);
    if !is_pointer(chunk) {
        println!("  not a pointer: ENTITY_CHUNK is wrong");
        return;
    }

    let mut live = 0;
    for slot in FIRST_SLOT..=PLAYER_SLOTS {
        let at = chunk + slot as u64 * schema::SLOT_STRIDE;
        let Some(controller) = process.read::<u64>(at).ok() else { continue };
        if !is_pointer(controller) {
            continue;
        }
        let handle = process.read::<u32>(controller + schema::PAWN_HANDLE).unwrap_or(0);
        let index = handle & schema::HANDLE_MASK;
        let pawn = process
            .read::<u64>(
                list + schema::ENTITY_CHUNK + 8 * u64::from(index >> schema::SLOT_SHIFT),
            )
            .ok()
            .filter(|c| is_pointer(*c))
            .and_then(|c| {
                process
                    .read::<u64>(c + schema::SLOT_STRIDE * u64::from(index & schema::SLOT_MASK))
                    .ok()
            })
            .unwrap_or(0);
        let health = process.read::<i32>(pawn.wrapping_add(schema::HEALTH)).unwrap_or(-1);
        let life = process.read::<u8>(pawn.wrapping_add(schema::LIFE_STATE)).unwrap_or(255);
        let team = process.read::<u8>(pawn.wrapping_add(schema::TEAM)).unwrap_or(255);
        if is_pointer(pawn) {
            live += 1;
        }
        println!(
            "  slot {slot:<3} controller 0x{controller:<12x} handle 0x{handle:<6x} \
             pawn 0x{pawn:<12x} health {health:<5} life {life:<4} team {team}"
        );
    }
    println!("  {live} slot(s) resolved to a pawn pointer");
}

/// The first frame, written out: the players found, the matrix, and the same bones as text.
fn log(process: &mut Process, client: &Module, view_projection: &Mat4, options: &Options) {
    if options.verbose {
        diagnose(process, client);
    }
    if !is_world_to_clip(view_projection) {
        println!("the matrix's first two rows are not perpendicular; try --transpose.");
    }
    let found = match players(process, client) {
        Ok(found) => found,
        Err(error) => {
            println!("\nno player could be read: {error}");
            return;
        }
    };
    println!("\n{} enemy player(s):", found.players.len());
    for player in &found.players {
        println!("  slot {:<4} pawn 0x{:<16x}", player.slot, player.pawn);
    }
    if found.boneless > 0 {
        println!(
            "  {} live pawn(s) had no skeleton shaped like a person: the scene node, the bone \
             array pointer or the bone layout is what to check.",
            found.boneless
        );
    }

    let frame = Frame::new(&found.players, view_projection, options);
    println!("\n{} bone lines.", frame.lines.len());
    let fraction = |p: (f32, f32)| (p.0 / options.width, p.1 / options.height);
    let mut canvas = Canvas::new();
    for (from, to) in &frame.lines {
        canvas.line(fraction(*from), fraction(*to));
    }
    println!("\n{}", canvas.render());
}

/// The value of an option that takes one.
fn value(arguments: &[String], index: &mut usize, name: &str) -> Result<String, String> {
    let value = arguments.get(*index).ok_or_else(|| format!("{name} needs a value."))?;
    *index += 1;
    Ok(value.clone())
}

/// A number from the command line.
fn number(text: &str) -> Result<f32, String> {
    text.parse::<f32>().map_err(|_| format!("{text} is not a number."))
}

/// A positive number, for a screen dimension.
fn positive(text: &str) -> Result<f32, String> {
    let value = number(text)?;
    (value > 0.0).then_some(value).ok_or_else(|| format!("{text} is not above zero."))
}

/// A `--size` value: width and height separated by `x`.
fn size(text: &str) -> Result<(f32, f32), String> {
    let (width, height) =
        text.split_once(['x', 'X']).ok_or_else(|| format!("{text} is not WxH."))?;
    Ok((positive(width)?, positive(height)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Options {
        Options { width: DEFAULT_WIDTH, height: DEFAULT_HEIGHT, transpose: false }
    }

    /// Writes one bone's position into the position field of its entry.
    fn place(entries: &mut BoneEntries, index: usize, position: Vec3) {
        for (axis, value) in position.iter().enumerate() {
            let at = index * BONE_STRIDE + BONE_POSITION + axis * 4;
            entries[at / BONE_STRIDE][at % BONE_STRIDE..][..4]
                .copy_from_slice(&value.to_le_bytes());
        }
    }

    /// Bone entries holding `bones` at the position field of each entry.
    fn entries(bones: &[(usize, Vec3)]) -> BoneEntries {
        let mut entries = [[0u8; BONE_STRIDE]; BONE_COUNT];
        for &(index, position) in bones {
            place(&mut entries, index, position);
        }
        entries
    }

    /// A standing person at the origin: the root at the feet, the head 72 units up, and every joint
    /// the connections use in between.
    fn person() -> BoneEntries {
        entries(&[
            (joint::ORIGIN, [0.0, 0.0, 0.0]),
            (joint::PELVIS, [0.0, 0.0, 44.0]),
            (joint::SPINE_1, [0.0, 0.0, 52.0]),
            (joint::SPINE_2, [0.0, 0.0, 58.0]),
            (joint::CHEST, [0.0, 0.0, 62.0]),
            (joint::NECK, [0.0, 0.0, 68.0]),
            (joint::HEAD, [0.0, 0.0, 72.0]),
            (joint::SHOULDER_L, [-8.0, 0.0, 62.0]),
            (joint::ELBOW_L, [-14.0, 0.0, 52.0]),
            (joint::HAND_L, [-18.0, 0.0, 44.0]),
            (joint::SHOULDER_R, [8.0, 0.0, 62.0]),
            (joint::ELBOW_R, [14.0, 0.0, 52.0]),
            (joint::HAND_R, [18.0, 0.0, 44.0]),
            (joint::HIP_L, [-5.0, 0.0, 40.0]),
            (joint::KNEE_L, [-6.0, 0.0, 22.0]),
            (joint::FOOT_L, [-6.0, 0.0, 3.0]),
            (joint::HIP_R, [5.0, 0.0, 40.0]),
            (joint::KNEE_R, [6.0, 0.0, 22.0]),
            (joint::FOOT_R, [6.0, 0.0, 3.0]),
        ])
    }

    /// A camera 250 units along `x` looking at the person's middle, in a `z`-up world.
    fn view_projection() -> Mat4 {
        let f = 1.0 / (30.0f32.to_radians()).tan();
        let aspect = DEFAULT_WIDTH / DEFAULT_HEIGHT;
        [
            [0.0, f / aspect, 0.0, 0.0],
            [0.0, 0.0, f, -6.0 * f],
            [0.0, 0.0, -1.0, 0.0],
            [-1.0, 0.0, 0.0, 250.0],
        ]
    }

    #[test]
    fn bones_decode_at_the_position_field() {
        let person = person();
        assert_eq!(bone(&person, joint::ORIGIN), [0.0, 0.0, 0.0]);
        assert_eq!(bone(&person, joint::HEAD), [0.0, 0.0, 72.0]);
        assert_eq!(bone(&person, joint::PELVIS), [0.0, 0.0, 44.0]);
    }

    #[test]
    fn a_person_is_told_from_a_misread_skeleton() {
        assert!(looks_like_a_player(&person(), [0.0; 3]));
        // A skeleton whose root is not near the entity's own origin is not one to trust.
        assert!(!looks_like_a_player(&person(), [0.0, 0.0, 4000.0]));
        // Nor is a head that is not about a player's height above the root.
        let squat = entries(&[(joint::ORIGIN, [0.0; 3]), (joint::HEAD, [0.0, 0.0, 20.0])]);
        assert!(!looks_like_a_player(&squat, [0.0; 3]));
    }

    #[test]
    fn one_line_is_drawn_per_connection() {
        let players = [Player { slot: 1, pawn: 0x1000, bones: person() }];
        let frame = Frame::new(&players, &view_projection(), &options());
        assert_eq!(frame.lines.len(), CONNECTIONS.len());
    }

    #[test]
    fn a_bone_behind_the_lens_takes_its_lines_with_it() {
        // The camera looks along -x from x = 250, and the neck joins four connections.
        let mut bones = person();
        place(&mut bones, joint::NECK, [251.0, 0.0, 68.0]);
        let players = [Player { slot: 1, pawn: 0x1000, bones }];
        let frame = Frame::new(&players, &view_projection(), &options());
        assert_eq!(frame.lines.len(), CONNECTIONS.len() - 4);
    }

    #[test]
    fn pixels_land_where_the_projection_says_and_pointers_are_plausible() {
        let view_projection = view_projection();
        let (x, y) =
            world_to_screen(&view_projection, [0.0, 0.0, 6.0], DEFAULT_WIDTH, DEFAULT_HEIGHT)
                .unwrap();
        assert!((x - DEFAULT_WIDTH / 2.0).abs() < 0.5 && (y - DEFAULT_HEIGHT / 2.0).abs() < 0.5);
        // The camera looks along -x, so anything past it is behind the lens.
        assert_eq!(
            world_to_screen(&view_projection, [251.0, 0.0, 6.0], DEFAULT_WIDTH, DEFAULT_HEIGHT),
            None
        );
        assert!(is_world_to_clip(&view_projection));
        // A matrix of zeros, read before a map loads, is not one.
        assert!(!is_world_to_clip(&[[0.0; 4]; 4]));
        assert!(is_pointer(0x0000_7ffa_1000_0000) && !is_pointer(0x100) && !is_pointer(0));
    }

    #[test]
    fn options_parse_the_size_and_refuse_a_bad_one() {
        let parsed =
            Options::parse(["--size", "1280x720"].map(String::from).to_vec()).unwrap().unwrap();
        assert_eq!((parsed.width, parsed.height), (1280.0, 720.0));
        for arguments in [vec!["--size"], vec!["--size", "1920"], vec!["--nope"]] {
            let arguments: Vec<String> = arguments.into_iter().map(String::from).collect();
            assert!(Options::parse(arguments).is_err());
        }
    }
}
