use corsairmi::{aio::PowerSupply, OpenError, RAILS};

#[tokio::main]
async fn main() -> Result<(), OpenError> {
    let mut list = corsairmi::list()?;
    if let Some(path) = list.pop() {
        let mut psu = PowerSupply::open(path).await?;
        println!("Model: {:?}", psu.model());
        println!("PC uptime: {:?}", psu.pc_uptime().await);
        println!("PSU uptime: {:?}", psu.uptime().await);
        println!("Name: {:?}", psu.name().await);
        println!("Product: {:?}", psu.product().await);
        println!("Vendor: {:?}", psu.vendor().await);
        println!("Temp1: {:?} C", psu.temp1().await);
        println!("Temp2: {:?} C", psu.temp2().await);
        println!("Fan: {:?} RPM", psu.rpm().await);
        println!("Input voltage: {:?} V", psu.input_voltage().await);
        println!("Input power: {:?} W", psu.input_power().await);
        println!("Input current: {:?} A", psu.input_current().await);

        for rail in RAILS.iter() {
            psu.output_select(*rail).await?;
            println!(
                "{} output voltage: {:?} V",
                *rail,
                psu.output_voltage().await
            );
            println!(
                "{} output current: {:?} A",
                *rail,
                psu.output_current().await
            );
            println!("{} output power: {:?} W", *rail, psu.output_power().await);
        }
        Ok(())
    } else {
        println!("No power supplies found");
        Ok(())
    }
}
