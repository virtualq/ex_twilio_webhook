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
            secret: String.t() | mfa() | function(),
            path_pattern: [String.t()],
            public_host: String.t() | mfa()
          }

    defstruct [:secret, :path_pattern, :public_host]
  end

  @impl true
  def init(opts) when is_list(opts) do
    path_pattern = opts |> Keyword.get(:at) |> validate_path_pattern()
    secret = opts |> Keyword.get(:secret) |> validate_secret()
    public_host = opts |> Keyword.get(:public_host) |> validate_public_url()

    %Settings{
      path_pattern: path_pattern,
      secret: secret,
      public_host: public_host
    }
  end

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

  def validate_webhook(
        %Plug.Conn{params: %{"AccountSid" => account_sid}} = conn,
        %Settings{} = settings
      ) do
    secret = get_twilio_token!(settings.secret, account_sid)
    url = normalize_url(settings.public_host, conn)

    with [signature] <- get_req_header(conn, "x-twilio-signature"),
         %{raw_body: payload} <- conn.private,
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

  defp validate_secret(value) do
    raise """
    The secret given to #{inspect(__MODULE__)} is invalid.
    Expected a `{module, function, args}` tuple, a 0-arity function,
    a 1-arity function, or a string.
    Got: #{inspect(value)}
    """
  end

  defp validate_public_url(value) do
    if normalized = normalize_url(value) do
      normalized
    else
      raise """
      The public url given to #{inspect(__MODULE__)} is invalid.
      Expected a fully qualified URL, e. g. `https://mycompany.com`.
      Got: #{inspect(value)}
      """
    end
  end

  defp normalize_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host}
      when scheme in ["http", "https"] and is_binary(host) ->
        "#{scheme}://#{host}"

      _ ->
        false
    end
  end

  defp normalize_url(_), do: false

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

  defp get_twilio_token!(token, _account_sid) when is_binary(token), do: token

  defp normalize_url(public_host, %Plug.Conn{} = conn) do
    normalized_query =
      case conn.query_string do
        blank when blank in ["", nil] -> ""
        query -> "?#{query}"
      end

    public_host <> conn.request_path <> normalized_query
  end
end
