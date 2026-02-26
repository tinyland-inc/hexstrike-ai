-- Render all tool capabilities into a single manifest for the MCP server
let meta = ./tools/meta.dhall
let network = ./tools/network.dhall
let recon = ./tools/recon.dhall
let web = ./tools/web.dhall
let api = ./tools/api.dhall
let crypto = ./tools/crypto.dhall
let credential = ./tools/credential.dhall
let smb = ./tools/smb.dhall
let container = ./tools/container.dhall
let binary = ./tools/binary.dhall
let forensics = ./tools/forensics.dhall
let intelligence = ./tools/intelligence.dhall

in  { tools = meta # network # recon # web # api # crypto # credential
              # smb # container # binary # forensics # intelligence
    , version = "0.2.0"
    , generatedBy = "dhall-to-json"
    }
