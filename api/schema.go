package api

import "encoding/json"

// Fallback Schema, Only to be used if we encounter a Broken Server (v5.0), Not API Stable!
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
}
