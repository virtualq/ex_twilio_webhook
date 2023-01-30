defmodule ExTwilioWebhook.HashHelpers do
  def hmac_sha1_base64(key, data) when is_binary(key) and is_binary(data) do
    digested = :crypto.mac(:hmac, :sha, key, data)
    Base.encode64(digested)
  end

  def get_expected_twilio_signature(auth_token, url, params)
      when is_binary(auth_token) and is_binary(url) do
    data = url <> normalize_data(params)
    hmac_sha1_base64(auth_token, data)
  end

  defp normalize_data(string) when is_binary(string), do: string
  defp normalize_data(list) when is_list(list), do: Enum.join(list)

  defp normalize_data(map) when is_map(map) do
    map
    |> Enum.map(fn {key, value} -> [to_string(key), to_string(value)] end)
    |> Enum.join()
  end

  def add_port(url) when is_binary(url) do
    parsed = URI.parse(url)

    normalized_host =
      case parsed.host do
        nil -> ""
        host -> "#{host}:#{parsed.port}"
      end

    normalized_query =
      case parsed.query do
        nil -> ""
        query -> "?#{query}"
      end

    normalized_fragment =
      case parsed.fragment do
        nil -> ""
        fragment -> "##{fragment}"
      end

    Enum.join([
      parsed.scheme,
      "://",
      normalized_host,
      parsed.path,
      normalized_query,
      normalized_fragment
    ])
  end

  def remove_port(url) when is_binary(url) do
    url
    |> URI.parse()
    |> Map.put(:port, nil)
    |> URI.to_string()
  end

  @signature_key "bodySHA256"

  def get_sha_hash_from_url(url) when is_binary(url) do
    url
    |> URI.parse()
    |> Map.get(:query)
    |> URI.decode_query()
    |> Map.get(@signature_key)
  end

  def validate_request_with_body(auth_token, signature, url, body)
      when is_binary(auth_token) and is_binary(signature) and is_binary(url) and is_binary(body) do
    case get_sha_hash_from_url(url) do
      nil ->
        # URL encoded body
        params = parse_and_sort_urlencoded_body(body)
        validate_url(auth_token, signature, url, params)

      sha_hash ->
        validate_url(auth_token, signature, url) &&
          validate_json_body(body, sha_hash)
    end
  end

  def validate_url(auth_token, signature, url, params \\ []) do
    signature_with_port = get_expected_twilio_signature(auth_token, add_port(url), params)
    signature_without_port = get_expected_twilio_signature(auth_token, remove_port(url), params)
    signature_with_port == signature || signature_without_port == signature
  end

  def validate_json_body(body, expected_signature)
      when is_binary(body) and is_binary(expected_signature) do
    digest = :crypto.hash(:sha256, body)
    Base.encode16(digest, case: :lower) == expected_signature
  end

  @spec parse_and_sort_urlencoded_body(body :: binary()) :: [binary()]
  def parse_and_sort_urlencoded_body(body) when is_binary(body) do
    body
    |> URI.decode_query()
    |> Enum.map(fn {key, value} -> key <> value end)
  end
end
