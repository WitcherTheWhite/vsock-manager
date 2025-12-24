use std::{sync::Arc, thread};

use dashmap::DashSet;

use crate::ta_server::run_ta_server;

mod protocal;
mod ta_server;

fn main() {
    let ta_registry = Arc::new(DashSet::<String>::new());

    let handle1 = thread::spawn({
        let registry = ta_registry.clone();
        move || {
            if let Err(e) = run_ta_server(registry) {
                eprintln!("TA server failed: {:?}", e);
            }
        }
    });

    handle1.join().expect("TA server thread panicked");
}
