# frozen_string_literal: true

def register(_params)
  @risk_score_threshold = Integer(ENV.fetch("RISK_SCORE_THRESHOLD", "50"))
  unless (1..100).cover?(@risk_score_threshold)
    raise ArgumentError, "RISK_SCORE_THRESHOLD must be between 1 and 100"
  end

  @weights = {
    threat_intel_match: 80,
    authentication_failure: 25,
    suspicious_process_parent: 60,
    suspicious_payload_pattern: 30
  }.freeze
  @shell_processes = %w[powershell pwsh cmd wscript cscript mshta].freeze
  @document_processes = %w[winword excel outlook powerpnt acrord32].freeze
  @threat_intel_fields = {
    "[source][ip]" => "[@metadata][threat_intel][source_ip]",
    "[destination][ip]" => "[@metadata][threat_intel][destination_ip]",
    "[client][ip]" => "[@metadata][threat_intel][client_ip]"
  }.freeze
  @suspicious_payload_pattern =
    /(?:union\s+select|<\s*script|(?:\.\.\/){3,}|-enc\s+[a-z0-9+\/=]{20,})/i.freeze
  @normalize_proc = lambda do |value|
    value.to_s.tr("\\", "/").split("/").last.to_s.downcase.sub(/\.exe\z/, "")
  end.freeze
end

def filter(event)
  categories = Array(event.get("[event][category]")).map { |value| value.to_s.downcase }
  outcome = event.get("[event][outcome]").to_s.downcase
  event_code = event.get("[event][code]").to_s
  score = 0
  reasons = []

  threat_ips = []
  threat_providers = []
  @threat_intel_fields.each do |field, metadata_field|
    provider = event.get(metadata_field)
    next unless provider && provider != "not_found"

    threat_ips << event.get(field)
    threat_providers << provider
  end

  unless threat_providers.empty?
    score += @weights[:threat_intel_match]
    reasons << "threat_intel_match"
    event.set("[threat][indicator][ip]", threat_ips.compact.uniq)
    event.set("[threat][indicator][provider]", threat_providers.uniq)
  end

  if (categories.include?("authentication") && outcome == "failure") || event_code == "4625"
    score += @weights[:authentication_failure]
    reasons << "authentication_failure"
  end

  process_name = @normalize_proc.call(event.get("[process][name]"))
  parent_name = @normalize_proc.call(event.get("[process][parent][name]"))
  if @shell_processes.include?(process_name) && @document_processes.include?(parent_name)
    score += @weights[:suspicious_process_parent]
    reasons << "suspicious_process_parent"
  end

  raw_text = [event.get("[message]"), event.get("[url][path]")].compact.join(" ")
  if raw_text.match?(@suspicious_payload_pattern)
    score += @weights[:suspicious_payload_pattern]
    reasons << "suspicious_payload_pattern"
  end

  score = [score, 100].min
  event.set("[event][risk_score]", score)
  event.set("[soc][risk][reasons]", reasons)
  status = score >= @risk_score_threshold ? "high" : (score > 0 ? "elevated" : "low")
  event.set("[soc][risk][status]", status)
  event.tag("risk_assessed")
  [event]
end
