use anyhow::Result;
use describe_me_lib::AppContext;

use crate::describe_me::args::{DescriptionCommand, MetadataCommand, TagsCommand};

pub fn handle_metadata_command(cmd: MetadataCommand, ctx: &AppContext) -> Result<()> {
    warn_if_metadata_not_persistent(ctx);
    match cmd {
        MetadataCommand::Description(action) => handle_description_command(action, ctx),
        MetadataCommand::Tags(action) => handle_tags_command(action, ctx),
    }
}

fn handle_description_command(cmd: DescriptionCommand, ctx: &AppContext) -> Result<()> {
    match cmd {
        DescriptionCommand::Show => {
            if let Some(desc) = describe_me_lib::load_server_description_with(ctx)? {
                println!("{desc}");
            } else {
                println!("(aucune description stockée)");
            }
        }
        DescriptionCommand::Set { text } => {
            describe_me_lib::set_server_description_with(ctx, &text)?;
            println!("Description enregistrée.");
        }
        DescriptionCommand::Clear => {
            describe_me_lib::clear_server_description_with(ctx)?;
            println!("Description supprimée.");
        }
    }
    Ok(())
}

fn warn_if_metadata_not_persistent(ctx: &AppContext) {
    use describe_me_lib::MetadataStoreHealth::*;
    match ctx.metadata_store_health() {
        Persistent => {}
        FallbackInMemory => eprintln!(
            "Avertissement: le stockage des métadonnées est en fallback mémoire (modifications non persistées)."
        ),
        InMemoryOnly => eprintln!(
            "Avertissement: le stockage des métadonnées est purement mémoire (modifications non persistées)."
        ),
    }
}

fn handle_tags_command(cmd: TagsCommand, ctx: &AppContext) -> Result<()> {
    match cmd {
        TagsCommand::Show => {
            let tags = describe_me_lib::load_server_tags_with(ctx)?;
            if tags.is_empty() {
                println!("(aucun tag configuré)");
            } else {
                println!("{}", tags.join(", "));
            }
        }
        TagsCommand::Set { tags } => {
            let normalized = describe_me_lib::set_server_tags_with(ctx, &tags)?;
            if normalized.is_empty() {
                println!("Aucun tag valide fourni, liste nettoyée.");
            } else {
                println!("Tags définis: {}", normalized.join(", "));
            }
        }
        TagsCommand::Add { tags } => {
            let normalized = describe_me_lib::add_server_tags_with(ctx, &tags)?;
            println!("Tags actuels: {}", normalized.join(", "));
        }
        TagsCommand::Remove { tags } => {
            let normalized = describe_me_lib::remove_server_tags_with(ctx, &tags)?;
            if normalized.is_empty() {
                println!("Plus aucun tag défini.");
            } else {
                println!("Tags restants: {}", normalized.join(", "));
            }
        }
        TagsCommand::Clear => {
            describe_me_lib::clear_server_tags_with(ctx)?;
            println!("Tags supprimés.");
        }
    }
    Ok(())
}
