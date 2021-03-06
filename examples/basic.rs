use corsairmi::{OpenError, PowerSupply, RAILS};

fn main() -> Result<(), OpenError> {
    let mut list = corsairmi::list()?;
    if let Some(path) = list.pop() {
        let mut psu = PowerSupply::open(path)?;
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
            psu.output_select(*rail)?;
            println!("{} output voltage: {:?} V", *rail, psu.output_voltage());
            println!("{} output current: {:?} A", *rail, psu.output_current());
            println!("{} output power: {:?} W", *rail, psu.output_power());
        }
        Ok(())
    } else {
        println!("No power supplies found");
        Ok(())
    }
}
