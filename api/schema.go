package api

import "encoding/json"

// ResourceSchemas is a fallback schema, only to be used if we encounter a broken server (v5.0). Not API stable!
var ResourceSchemas = map[string]json.RawMessage{
	"v5-default": json.RawMessage(`
{
  "resource": {
    "type": "object",
    "required": ["name"],
    "properties": {
      "name": {
        "type": "string",
        "maxLength": 255
      },
      "username": {
        "type": ["string", "null"],
        "maxLength": 255
      },
      "uris": {
        "type": "array",
        "items": {
          "type": "string",
          "maxLength": 1024
        }
      },
      "description": {
        "type": ["string", "null"],
        "maxLength": 10000
      }
    }
  },
  "secret": {
    "type": "object",
    "required": ["password"],
    "properties": {
      "object_type": {
        "type": "string",
        "enum": ["PASSBOLT_SECRET_DATA"]
      },
      "password": {
        "type": ["string", "null"],
        "maxLength": 4096
      },
      "description": {
        "type": ["string", "null"],
        "maxLength": 10000
      }
    }
  }
}`),
	"v5-password-string": json.RawMessage(`
{
  "resource": {
    "type": "object",
    "required": ["name"],
    "properties": {
      "name": {
        "type": "string",
        "maxLength": 255
      },
      "username": {
        "type": ["string", "null"],
        "maxLength": 255
      },
      "uris": {
        "type": "array",
        "items": {
          "type": "string",
          "maxLength": 1024
        }
      },
      "description": {
        "type": ["string", "null"],
        "maxLength": 10000
      }
    }
  },
  "secret": {
    "type": "string",
    "maxLength": 4096
  }
}`),
	"v5-default-with-totp": json.RawMessage(`
{
  "resource": {
    "type": "object",
    "required": ["name"],
    "properties": {
      "name": {
        "type": "string",
        "maxLength": 255
      },
      "username": {
        "type": ["string", "null"],
        "maxLength": 255
      },
      "uris": {
        "type": "array",
        "items": {
          "type": "string",
          "maxLength": 1024
        }
      },
      "description": {
        "type": ["string", "null"],
        "maxLength": 10000
      }
    }
  },
  "secret": {
    "type": "object",
    "required": ["totp"],
    "properties": {
      "object_type": {
        "type": "string",
        "enum": ["PASSBOLT_SECRET_DATA"]
      },
      "password": {
        "type": ["string", "null"],
        "maxLength": 4096
      },
      "description": {
        "type": ["string", "null"],
        "maxLength": 10000
      },
      "totp": {
        "type": "object",
        "required": ["secret_key", "digits", "algorithm"],
        "properties": {
          "algorithm": {
            "type": "string",
            "minLength": 4,
            "maxLength": 6
          },
          "secret_key": {
            "type": "string",
            "maxLength": 1024
          },
          "digits": {
            "type": "number",
            "minimum": 6,
            "maximum": 8
          },
          "period": {
            "type": "number"
          }
        }
      }
    }
  }
}`),
	"v5-totp-standalone": json.RawMessage(`
{
  "resource": {
    "type": "object",
    "required": ["name"],
    "properties": {
      "name": {
        "type": "string",
        "maxLength": 255
      },
      "uris": {
        "type": "array",
        "items": {
          "type": "string",
          "maxLength": 1024
        }
      },
      "description": {
        "type": ["string", "null"],
        "maxLength": 10000
      }
    }
  },
  "secret": {
    "type": "object",
    "required": ["totp"],
    "properties": {
      "object_type": {
        "type": "string",
        "enum": ["PASSBOLT_SECRET_DATA"]
      },
      "totp": {
        "type": "object",
        "required": ["secret_key", "digits", "algorithm"],
        "properties": {
          "algorithm": {
            "type": "string",
            "minLength": 4,
            "maxLength": 6
          },
          "secret_key": {
            "type": "string",
            "maxLength": 1024
          },
          "digits": {
            "type": "number",
            "minimum": 6,
            "maximum": 8
          },
          "period": {
            "type": "number"
          }
        }
      }
    }
  }
}`),
	"v5-custom-fields": json.RawMessage(`
{
  "resource": {
    "type": "object",
    "required": ["name", "custom_fields"],
    "properties": {
      "object_type": {
        "type": "string",
        "enum": ["PASSBOLT_RESOURCE_METADATA"]
      },
      "name": {
        "type": "string",
        "maxLength": 255
      },
      "uris": {
        "type": "array",
        "items": {
          "type": "string",
          "maxLength": 1024
        }
      },
      "description": {
        "type": ["string", "null"],
        "maxLength": 10000
      },
      "custom_fields": {
        "type": "array",
        "maxItems": 128,
        "items": {
          "type": "object",
          "required": ["id", "type"],
          "properties": {
            "id": { "type": "string" },
            "type": {
              "type": "string",
              "enum": ["text", "password", "boolean", "number", "uri"]
            },
            "metadata_key": { "type": ["string", "null"] },
            "metadata_value": {}
          }
        }
      }
    }
  },
  "secret": {
    "type": "object",
    "required": ["custom_fields"],
    "properties": {
      "object_type": {
        "type": "string",
        "enum": ["PASSBOLT_SECRET_DATA"]
      },
      "custom_fields": {
        "type": "array",
        "maxItems": 128,
        "items": {
          "type": "object",
          "required": ["id", "type"],
          "properties": {
            "id": { "type": "string" },
            "type": {
              "type": "string",
              "enum": ["text", "password", "boolean", "number", "uri"]
            },
            "secret_key": { "type": ["string", "null"] },
            "secret_value": {}
          }
        }
      }
    }
  }
}`),
}
