defmodule ExTwilioWebhook.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_twilio_webhook,
      version: "0.0.3",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "ExTwilioWebhook is a simple library that validates Twilio webhooks in Plug applications.",
      package: package()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.0"},
      {:jason, "~> 1.0", only: :test},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["BSD-3-Clause"],
      links: %{
        "Github" => "https://github.com/moroz/ex_twilio_webhook"
      }
    ]
  end
end
