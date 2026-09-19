> ## Documentation Index
> Fetch the complete documentation index at: https://docs.tokenfactory.nebius.com/llms.txt
> Use this file to discover all available pages before exploring further.

# Introduction

<Note>
  Nebius Token Factory offers an [OpenAI-compatible API](https://docs.tokenfactory.nebius.com/api-reference/models/list-models) for inference and fine-tuning.
</Note>

Here are examples of Python, cURL and JavaScript SDK command that makes an API request from your terminal:

<CodeGroup>
  ```python Python theme={null}
  import os
  from openai import OpenAI

  client = OpenAI(
      base_url="https://api.tokenfactory.nebius.com/v1/",
      api_key=os.environ.get("NEBIUS_API_KEY"),
  )

  completion = client.chat.completions.create(
      model="meta-llama/Meta-Llama-3.1-70B-Instruct",
      messages=[
          {
              "role": "user",
              "content": """Hello!"""
          }
      ],
      temperature=0.6
  )

  print(completion.to_json())
  ```

  ```bash cURL theme={null}
  curl 'https://api.tokenfactory.nebius.com/v1/chat/completions' \
    -X 'POST' \
    -H 'Content-Type: application/json' \
    -H 'Accept: */*' \
    -H "Authorization: Bearer $NEBIUS_API_KEY" \
    --data-binary '{"temperature":0.6,"model":"meta-llama/Meta-Llama-3.1-70B-Instruct","messages":[{"role":"user","content":"Hello!"}]}'
  ```

  ```javascript JavaScript theme={null}
  const OpenAI = require("openai");
  const client = new OpenAI({
    baseURL: "https://api.tokenfactory.nebius.com/v1/",
    apiKey: process.env.NEBIUS_API_KEY,
  });

  client.chat.completions.create({
    "temperature": 0.6,
    "model": "meta-llama/Meta-Llama-3.1-70B-Instruct",
    "messages": [
      {
        "role": "user",
        "content": "Hello!"
      }
    ]
  })
  .then((completion) => console.log(completion));
  ```
</CodeGroup>

<Accordion title="Response">
  ```
  {
    "choices": [
      {
        "finish_reason": "stop",
        "index": 0,
        "message": {
          "content": "Hello! It's nice to meet you. Is there something I can help you with, or would you like to chat?",
          "role": "assistant"
        }
      }
    ],
    "created": 1717516032,
    "model": "meta-llama/Meta-Llama-3-70B-Instruct-cheap",
    "object": "chat.completion",
    "usage": {
      "completion_tokens": 26,
      "prompt_tokens": 13,
      "total_tokens": 39
    }
  }

  ```
</Accordion>

For more examples, see [Examples of using the Nebius Token Factory API](https://docs.tokenfactory.nebius.com/api-reference/examples/overview).

## Authentication

To authenticate, include your *API key* (e.g., `ABC123...`) in the `Authorization` header, as shown below:

```
Authorization: Bearer ABC123...
```

<Warning>
  Keep your keys private; do not share or expose them in client-side code. If a key is compromised, Nebius Token Factory can automatically revoke it
</Warning>

To get an API key:

1. In Nebius Token Factory, go to the [API keys](https://tokenfactory.nebius.com/project/api-keys) section.
2. Click  **Create API key**.
3. Enter the key name and then click **Create**.
4. Save the displayed API key. You cannot open it later in Nebius Token Factory.

<Tip>
  In the [Nebius Token Factory inference playground](https://tokenfactory.nebius.com/playground), you can view your model setup and chat as code that makes API requests, and use this code in your applications. For more details, see [View code](https://docs.tokenfactory.nebius.com/ai-models-inference/playground#view-code).
</Tip>

<Tip>
  You can use [integrations with third-party instruments](https://docs.tokenfactory.nebius.com/integrations/overview) instead of the API.
</Tip>
