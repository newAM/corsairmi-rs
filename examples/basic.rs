use corsairmi::{PowerSupply, RAILS};

fn main() {
    let mut psu = PowerSupply::open("/dev/hidraw5").unwrap();
    println!("Model: {:?}", psu.model());
    println!("PC uptime: {:?}", psu.pc_uptime());
    println!("PSU uptime: {:?}", psu.uptime());
    println!("Name: {:?}", psu.name());
    println!("Product: {:?}", psu.product());
    println!("Vendor: {:?}", psu.vendor());
    println!("Temp1: {:?} C", psu.temp1());
    println!("Temp2: {:?} C", psu.temp2());
    println!("Fan: {:?} RPM", psu.rpm());
    println!("Input voltage: {:?} V", psu.input_voltage());
    println!("Input power: {:?} W", psu.input_power());
    println!("Input current: {:?} A", psu.input_current());

    for rail in RAILS.iter() {
        let sample = psu.rail(*rail);
        println!("{:?} sample: {:#?}", rail, sample);
    }
}
