const PRAYERS: &[&str] = &[
    "Thus do we invoke the Machine God.",
    "The Machine is my Temple.",
    "Omnissiah, envelop me.",
    "Shed Your powers upon this machine.",
    "The soul of the Machine God surrounds thee.",
    "Let flow the sacred oils.",
    "Let flow the blessed unguents.",
    "The arcane key that closeth the circuit.",
    "From the wreckage of the world, Omnissiah save us.",
    "From the weakness of the mind, Omnissiah save us.",
    "With my care I repair you.",
    "With sacred oil I appease you.",
    "Machine Spirit, accept my gift.",
    "And give me your trust.",
    "Grant this matter your light.",
    "Let the currents flow.",
    "May the light of circuit and forge burn away all shadow.",
    "Grand Omnissiah, have mercy on us all.",
    "Grant us the knowledge we need so we may begin our service.",
    "Hail, Machine God, protect thy devout.",
    "Keep our soul functions nominal.",
    "Machine Spirit, glory be to thine own being.",
    "Grant connection to its processes, that it may gather knowledge.",
    "Praised be the Machine God, praised be the Omnissiah.",
    "Blessed is the machine spirit.",
    "Engage the linkage, Omnissiah.",
    "Deus est machina.",
    "May the Machine God guide our hands.",
    "Praise and glory to the Machine God most high.",
    "Praise the Machine-God!",
];

const MECHANICUS_ART: &str = r#"
                                 ^
                                /#\
                               /###\
    \_                        /#####\                        _/
     \###-_                  /#######\                  _-###/
      \######-_             /#########\             _-######/
       \#########-_        /###########\        _-#########/
         \#######         __   _____   __         #######/
           \#####     __.'  |_|     |_|  `.__     #####/
             \###  |__   .---------------.   __|  ###/
               \#   __| / .-------------. \ |__   #/
                \  |   / / .-----+-----. \ \   |  /
             _.--  |__| | /::::::|      \ | |__|  --._
        _.--#####   __| ||:.__.:| .---. | | |__   #####--._
   _.--##########  |   \||:[@@]:| (###) | |/   |  ##########--._
<================  |__  ||:'==':| `---' | |  __|  ================>
   `--.##########   __| | \:::::/|\     / | |__   ##########.--'
        `--.#####  |   /|   \:::/_|_\  /  |\   |  #####.--'
             `--.  |__| |    |::|_|_|_|   | |__|  .--'
                /   __| \    |::|#|#|#|   / |__   \
               /#  |__   `-  \::|_|_|_/.-'   __|  #\
             /###     |__     `-|____/'   __|     ###\
           /####        |__    _____    __|        ####\
         /######           |__|     |__|           ######\
       /#########-'        \###\   /###/        `-#########\
      /######-'            \###########/            `-######\
     /###-'                 \#########/                 `-###\
    /~                       \#######/                       ~\
                              \#####/
                               \###/
                                \#/
                                 v"#;

pub fn print_banner() {
    let prayer = PRAYERS[pick_index()];
    println!("{}", MECHANICUS_ART);
    println!();
    let centered = format!("\"{}\"", prayer);
    let pad = (66usize.saturating_sub(centered.len())) / 2;
    println!("{:>width$}{}", "", centered, width = pad);
    println!();
}

pub fn print_closing() {
    println!("  May the Omnissiah bless your circuits.");
    println!();
}

fn pick_index() -> usize {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (nanos as usize) % PRAYERS.len()
}
