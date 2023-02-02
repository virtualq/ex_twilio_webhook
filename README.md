# ExTwilioWebhook

ExTwilioWebhook is a simple library that validates Twilio webhooks in Plug applications.
It has been developed for internal use at virtualQ GmbH, but it may come in handy for
someone else.

## Installation

Add `:ex_twilio_webhook` to project dependencies in `mix.exs`.

```elixir
def deps do
  [
    {:ex_twilio_webhook, github: "moroz/ex_twilio_webhook"}
  ]
end
```

In order to validate a webhook, the library needs access to both the parsed params
and to the unprocessed raw body of the request. However, by default, `Plug.Parsers`
discards the raw body when it parses the params. If your application is using Phoenix,
modify the call to `Plug.Parsers` in your application's endpoint module to add the `:body_reader` option:

```elixir
plug Plug.Parsers,
  parsers: [:urlencoded, :json],
  pass: ["*/*"],
  json_decoder: Phoenix.json_library(),
  body_reader: {ExTwilioWebhook.BodyReader, :read_body, []}
```

Add the `ExTwilioWebhook.Plug` to the endpoint after `Plug.Parsers`:

```
plug ExTwilioWebhook.Plug,
  at: ~r"^/twilio/",
  secret: fn account_sid ->
    do_some_logic(account_sid)
  end,
  public_host: {System, :get_env, ["PUBLIC_HOST"]}
```

Configuration options:

- `at`: the request path at which the plug will validate webhook signatures.
  When given a string, it will only match if the `request_path`
  is equal to the pattern. When given a regular expression, it will match if
  the regular expression matches the `request_path`.

- `secret`: Twilio secret. The secret can be provided as a string, an `{m, f, a}`
  tuple, or an anonymous function of arity 0 or 1. When given a 1-arity function,
  the function will be called with the value of the `AccountSid` of each request.
  This is useful if your application needs to process webhooks from multiple
  Twilo accounts. When given an `{m, f, a}` tuple, the tuple will be called
  at runtime for each request.

- `public_host`: The public URL of your application with scheme, e. g.:
  `https://myapp.com`. Can be provided as string or `{m, f, a}` tuple.
  When given a tuple, the tuple will be called at runtime for each request.

