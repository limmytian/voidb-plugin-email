use std::fs;
use std::path::Path;
use voidb_plugin_email::email_capabilities;

fn main() -> anyhow::Result<()> {
    let schemas_dir = Path::new("schemas");
    fs::create_dir_all(schemas_dir)?;

    let capabilities = email_capabilities();

    // Export capability schemas
    for cap in &capabilities {
        let input_path = schemas_dir.join(format!("{}-input.schema.json", cap.id));
        let output_path = schemas_dir.join(format!("{}-output.schema.json", cap.id));

        fs::write(&input_path, serde_json::to_string_pretty(&cap.input_schema)? + "\n")?;
        fs::write(&output_path, serde_json::to_string_pretty(&cap.output_schema)? + "\n")?;
        println!("Exported schemas for capability: {}", cap.id);
    }

    // Export profile schema
    let profile_schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "EmailConnectionProfile",
        "type": "object",
        "required": ["email", "password", "protocol", "receive", "smtp"],
        "properties": {
            "email": { "type": "string", "description": "Email address / username" },
            "password": { "type": "string", "description": "Password or app-specific token" },
            "protocol": {
                "type": "string",
                "enum": ["IMAP", "POP3"],
                "description": "Receive protocol"
            },
            "receive": {
                "type": "object",
                "required": ["host", "port"],
                "properties": {
                    "host": { "type": "string" },
                    "port": { "type": "integer", "minimum": 1, "maximum": 65535 }
                }
            },
            "smtp": {
                "type": "object",
                "required": ["host", "port"],
                "properties": {
                    "host": { "type": "string" },
                    "port": { "type": "integer", "minimum": 1, "maximum": 65535 }
                }
            },
            "receive_security": {
                "type": "string",
                "enum": ["PLAIN", "SSL/TLS", "STARTTLS"],
                "default": "SSL/TLS"
            },
            "smtp_security": {
                "type": "string",
                "enum": ["PLAIN", "SSL/TLS", "STARTTLS"],
                "default": "STARTTLS"
            },
            "verify_tls": {
                "type": "boolean",
                "default": true
            }
        },
        "additionalProperties": false
    });

    let profile_path = schemas_dir.join("profile.schema.json");
    fs::write(&profile_path, serde_json::to_string_pretty(&profile_schema)? + "\n")?;
    println!("Exported profile schema to {}", profile_path.display());

    Ok(())
}
