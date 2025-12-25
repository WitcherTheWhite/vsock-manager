use mbedtls::{
    Result,
    hash::{Md, Type},
};

const KYLINOS: &str = "www.kylinos.cn";
const PKG: &str = "cc-utils";
const BOX: &str = "libteec";

pub fn generate_psk() -> Result<Vec<u8>> {
    let mut psk = vec![0u8; 32];
    let mut ctx = Md::new(Type::SM3)?;

    ctx.update(KYLINOS.as_bytes())?;
    ctx.update(PKG.as_bytes())?;
    ctx.update(BOX.as_bytes())?;
    let _len = ctx.finish(&mut psk);

    Ok(psk)
}

pub const fn get_psk_identity() -> &'static str {
    PKG
}
