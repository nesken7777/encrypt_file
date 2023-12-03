use std::{
    env::args,
    error::Error,
    fs::OpenOptions,
    io::{stdin, stdout, BufRead, BufReader, BufWriter, Read, Write},
};

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};

use rand::{distributions::Standard, thread_rng, Rng};
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn Error>> {
    let arg = args().collect::<Vec<_>>();
    let wanna_decrypt = arg.get(3).map_or(false, |x| (x == "decrypt"));
    let file = arg.get(1).ok_or("入力ファイル名が必要だよ")?;
    let dest_file = arg.get(2).ok_or("出力先ファイル名が必要だよ")?;
    let mut ioout = BufWriter::new(stdout().lock());
    let ioout = &mut ioout;
    ioout.write("パスワードを入力してね:".as_bytes()).unwrap();
    ioout.flush().unwrap();
    let mut ioin = BufReader::new(stdin().lock());
    let mut s = String::new();
    ioin.read_line(&mut s).unwrap();
    let password = s.trim();
    if wanna_decrypt {
        decrypt(file, dest_file, password)?;
    } else {
        encrypt(file, dest_file, password)?;
    };
    ioout.write("完了".as_bytes()).unwrap();
    ioout.flush().unwrap();
    Ok(())
}

fn encrypt(file: &str, dest_file: &str, password: &str) -> Result<(), Box<dyn Error>> {
    let file = OpenOptions::new().read(true).open(file)?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::with_capacity(1024);
    reader.read_to_end(&mut buffer).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let cipher = Aes256GcmSiv::new(&result);
    let mut rng = thread_rng();
    let mut nonce_vec = (&mut rng)
        .sample_iter(Standard)
        .take(12)
        .collect::<Vec<u8>>();
    let nonce = Nonce::from_slice(nonce_vec.as_slice()); // 96-bits; unique per message
    let dest_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest_file)?;
    let cipher = cipher.encrypt(nonce, buffer.as_ref())?;
    let cipher = {
        nonce_vec.extend_from_slice(&cipher);
        nonce_vec
    };
    let mut writer = BufWriter::new(dest_file);
    writer.write_all(&cipher)?;
    Ok(())
}

fn decrypt(file: &str, dest_file: &str, password: &str) -> Result<(), Box<dyn Error>> {
    let file = OpenOptions::new().read(true).open(file)?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::with_capacity(1024);
    reader.read_to_end(&mut buffer).unwrap();
    let (nonce, file) = buffer.split_at(12);
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let cipher = Aes256GcmSiv::new(&result);
    let nonce = GenericArray::from_slice(nonce);
    let dest_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest_file)?;
    let plain = cipher.decrypt(nonce, file)?;
    let mut writer = BufWriter::new(dest_file);
    writer.write_all(&plain)?;
    Ok(())
}
