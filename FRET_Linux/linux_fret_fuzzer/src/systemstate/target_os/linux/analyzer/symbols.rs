use anyhow::{Context, Result};
use goblin::elf::Elf;
use libafl_qemu::GuestAddr;
use log::{debug, info};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// parse ELF file and extract symbol addresses
pub struct SymbolTable {
    symbols: HashMap<String, GuestAddr>,
}

impl SymbolTable {
    // load symbols from ELF file
    pub fn from_elf(path: &Path) -> Result<Self> {
        info!("Parsing ELF file: {}", path.display());
        
        // Read ELF file
        let buffer = fs::read(path)
            .context(format!("Failed to read ELF file: {}", path.display()))?;
        
        // Parse ELF
        let elf = Elf::parse(&buffer)
            .context("Failed to parse ELF file")?;
        
        let mut symbols = HashMap::new();
        
        // Iterate through symbol table
        for sym in elf.syms.iter() {
            // Get symbol name
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                
                let sym_type = sym.st_type();
                if sym_type == goblin::elf::sym::STT_FUNC 
                   || sym_type == goblin::elf::sym::STT_OBJECT
                   || sym_type == goblin::elf::sym::STT_NOTYPE {
                   
                    if sym.st_value != 0 {
                        let addr = sym.st_value as GuestAddr;
                        debug!("  Symbol: {:30} @ 0x{:016x}", name, addr);
                        symbols.insert(name.to_string(), addr);
                    }
                }
            }
        }

        
        info!("Loaded {} symbols from ELF", symbols.len());
        
        Ok(Self { symbols })
    }
    
   
    pub fn get(&self, name: &str) -> Result<GuestAddr> {
        self.symbols
            .get(name)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Symbol not found: {}", name))
    }
    
    
    pub fn get_or(&self, name: &str, default: GuestAddr) -> GuestAddr {
        self.symbols.get(name).copied().unwrap_or(default)
    }
    
    
    pub fn contains(&self, name: &str) -> bool {
        self.symbols.contains_key(name)
    }
    
   
    pub fn list_all(&self) -> Vec<(String, GuestAddr)> {
        let mut list: Vec<_> = self.symbols.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        list.sort_by_key(|(_, addr)| *addr);
        list
    }
}
