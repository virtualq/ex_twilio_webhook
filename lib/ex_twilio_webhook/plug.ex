defmodule ExTwilioWebhook.Plug do
  @moduledoc """
  A module plug that verifies Twilio webhook signatures and halts
  the request if the signature is invalid.

  This plug relies on parsed params, so it must be placed in your
  Phoenix pipeline after `Plug.Parsers`.
  """
  alias ExTwilioWebhook.HashHelpers

  @behaviour Plug

  import Plug.Conn

  defmodule Settings do
    @type t :: %__MODULE__{
            secret: String.t() | [String.t()] | mfa() | function(),
            path_pattern: [String.t()],
            public_host: String.t() | mfa(),
            raw_body: function() | mfa() | nil
          }

    defstruct [:secret, :path_pattern, :public_host, :raw_body]
  end

  @doc """
  Parses the plug's configuration options:

  - `at`: the request path at which the plug will validate webhook signatures.
    When given a string, it will only match if the `request_path`
    is equal to the pattern. When given a regular expression, it will match if
    the regular expression matches the `request_path`.

  - `secret`: Twilio secret. The secret can be provided as a string, a list of strings,
    an `{m, f, a}` tuple, or an anonymous function of arity 0 or 1.
    When given a 1-arity function, the function will be called with the value
    of the `AccountSid` of each request. This is useful if your application
    needs to process webhooks from multiple Twilo accounts. When given an `{m, f, a}`
    tuple, the tuple will be `apply`-ed at runtime for each request.

  - `public_host`: The public URL of your application with scheme, e. g.:
    `https://myapp.com`. Can be provided as string or `{m, f, a}` tuple.
    When given a tuple, the tuple will be called at runtime for each request.

  - `raw_body`: An optional function for fetching the raw body from a conn.
    by default the raw body is cached at conn.private.raw_body if using
    `ExTwilioWebhook.BodyReader` if it is stored somewhere else, this can
    be used to fetch that.

  This function will raise if called with invalid arguments.
  """
  @impl true
  def init(opts) when is_list(opts) do
    path_pattern = opts |> Keyword.get(:at) |> validate_path_pattern()
    secret = opts |> Keyword.get(:secret) |> validate_secret()
    public_host = opts |> Keyword.get(:public_host) |> validate_public_url()
    raw_body = opts |> Keyword.get(:raw_body) |> validate_raw_body()

    %Settings{
      path_pattern: path_pattern,
      secret: secret,
      public_host: public_host,
      raw_body: raw_body
    }
  end

  @doc """
  Checks whether a request matches the given path pattern and passes it through
  if it doesn't.
  """
  @impl true
  def call(%Plug.Conn{request_path: pattern} = conn, %Settings{path_pattern: pattern} = settings) do
    validate_webhook(conn, settings)
  end

  def call(%Plug.Conn{} = conn, %Settings{path_pattern: %Regex{} = regex} = settings) do
    if String.match?(conn.request_path, regex) do
      validate_webhook(conn, settings)
    else
      conn
    end
  end

  def call(conn, _settings), do: conn

  @doc """
  Does the actual webhook validation.
  """
  def validate_webhook(
        %Plug.Conn{params: params} = conn,
        %Settings{} = settings
      ) do
    # resolve twilio secret token for the request's `AccountSid`
    secret = get_twilio_token!(settings.secret, Map.get(params, "AccountSid"))

    # normalize request path to Twilio's canonical form
    url = normalize_request_url(settings.public_host, conn)

    # extract signature and raw body from the conn, and validate the signature
    with [signature] <- get_req_header(conn, "x-twilio-signature"),
         payload = get_raw_body(settings.raw_body, conn),
         true <-
           HashHelpers.validate_request_with_body(secret, signature, url, payload) do
      conn
    else
      _ ->
        deny_access(conn)
    end
  end

  def validate_webhook(conn, _settings), do: deny_access(conn)

  defp deny_access(conn) do
    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(403, "Twilio Request Validation Failed.")
    |> halt()
  end

  # Helper functions for request signature validation

  def normalize_request_url({m, f, a}, %Plug.Conn{} = conn) do
    host = apply(m, f, a)
    normalize_request_url(host, conn)
  end

  def normalize_request_url(public_host, %Plug.Conn{} = conn) do
    normalized_query =
      case conn.query_string do
        blank when blank in ["", nil] -> ""
        query -> "?#{query}"
      end

    public_host <> conn.request_path <> normalized_query
  end

  def path_matched?(path, %Regex{} = regex) do
    String.match?(path, regex)
  end

  def path_matched?(pattern, pattern), do: true
  def path_matched?(_, _), do: false

  defp get_twilio_token!({m, f, a}, _account_sid), do: apply(m, f, a)
  defp get_twilio_token!(fun, _account_sid) when is_function(fun, 0), do: fun.()

  defp get_twilio_token!(fun, account_sid) when is_function(fun, 1) do
    fun.(account_sid)
  end

  defp get_twilio_token!(token_or_list, _account_sid)
       when is_binary(token_or_list) or is_list(token_or_list),
       do: token_or_list

  defp get_raw_body({m, f, a}, conn), do: apply(m, f, [conn | a])
  defp get_raw_body(fun, conn) when is_function(fun, 1), do: fun.(conn)
  defp get_raw_body(_fun, conn), do: Map.get(conn.private, :raw_body)

  # Helper functions for parsing configuration options

  defp validate_path_pattern(string) when is_binary(string), do: string
  defp validate_path_pattern(%Regex{} = regex), do: regex

  defp validate_path_pattern(value) do
    raise """
    The path pattern given to #{inspect(__MODULE__)} is invalid.
    Expected a string or a regular expression.
    Got: #{inspect(value)}
    """
  end

  defp validate_secret({m, f, a}) when is_atom(m) and is_atom(f) and is_list(a) do
    {m, f, a}
  end

  defp validate_secret(fun) when is_function(fun, 0) or is_function(fun, 1) do
    fun
  end

  defp validate_secret(token) when is_binary(token), do: token

  defp validate_secret(list) when is_list(list) do
    if Enum.all?(list, &is_binary/1) do
      list
    else
      raise_secret_validation_error(list)
    end
  end

  defp validate_secret(other), do: raise_secret_validation_error(other)

  defp raise_secret_validation_error(value) do
    raise """
    The secret given to #{inspect(__MODULE__)} is invalid.
    Expected a `{module, function, args}` tuple, a 0-arity function,
    a 1-arity function, a string, or a list of strings.
    Got: #{inspect(value)}
    """
  end

  defp validate_raw_body({m, f, a}) when is_atom(m) and is_atom(f) and is_list(a) do
    {m, f, a}
  end

  defp validate_raw_body(fun) when is_function(fun, 1), do: fun

  defp validate_raw_body(nil), do: nil

  defp validate_raw_body(value) do
    raise """
    The raw body function given to #{inspect(__MODULE__)} is invalid.
    Expected a 1-arity function or an mfa tuple.
    Got: #{inspect(value)}
    """
  end

  defp validate_public_url(value) do
    if normalized = normalize_public_url(value) do
      normalized
    else
      raise """
      The public url given to #{inspect(__MODULE__)} is invalid.
      Expected a fully qualified URL, e. g. `https://mycompany.com`,
      or a `{module, function, args}` tuple.
      Got: #{inspect(value)}
      """
    end
  end

  defp normalize_public_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host}
      when scheme in ["http", "https"] and is_binary(host) ->
        "#{scheme}://#{host}"

      _ ->
        false
    end
  end

  defp normalize_public_url({m, f, a}) when is_atom(m) and is_atom(f) and is_list(a) do
    {m, f, a}
  end

  defp normalize_public_url(_), do: false
end
