require 'atlassian/jwt'
require 'jwt'
require 'rest_client'
require 'json'
require 'active_support/all'
require 'octokit'
require 'sinatra'
require 'sinatra/cookies'
require 'uri'
require 'yaml'
require 'securerandom'
require 'httparty'
require 'octicons_helper/helper'

$stdout.sync = true
$default_branch_name = "JIRA-BOT-BRANCH"

begin
  yml = File.open('jira-bot.yaml')
  contents = YAML.load(yml)

  GITHUB_CLIENT_ID = contents["client_id"]
  GITHUB_CLIENT_SECRET = contents["client_secret"]
  GITHUB_APP_KEY = File.read(contents["private_key"])
  GITHUB_APP_ID = contents["app_id"]
  GITHUB_APP_URL = contents["app_url"]
  COOKIE_SECRET = contents["cookie_secret"]
rescue
  begin
    GITHUB_CLIENT_ID = ENV.fetch("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET =  ENV.fetch("GITHUB_CLIENT_SECRET")
    GITHUB_APP_KEY = ENV.fetch("GITHUB_APP_KEY")
    GITHUB_APP_ID = ENV.fetch("GITHUB_APP_ID")
    GITHUB_APP_URL = ENV.fetch("GITHUB_APP_URL")
    COOKIE_SECRET = ENV.fetch("COOKIE_SECRET")
    ATLASSIAN_CLIENT_KEY = ENV.fetch("ATLASSIAN_CLIENT_KEY", "")
    ATLASSIAN_SHARED_SECRET = ENV.fetch("ATLASSIAN_SHARED_SECRET", "")
  rescue KeyError
    $stderr.puts "To run this script, please set the following environment variables:"
    $stderr.puts "- GITHUB_CLIENT_ID: GitHub Developer Application Client ID"
    $stderr.puts "- GITHUB_CLIENT_SECRET: GitHub Developer Application Client Secret"
    $stderr.puts "- GITHUB_APP_KEY: GitHub App Private Key"
    $stderr.puts "- GITHUB_APP_ID: GitHub App ID"
    $stderr.puts "- GITHUB_APP_URL: GitHub App URL"
    $stderr.puts "- COOKIE_SECRET: Integrity check for Session Cookies"
    exit 1
  end
end

configure do
  enable :cross_origin
end

before do
  response.headers['Access-Control-Allow-Origin'] = 'https://*.atlassian.net'
end

options "*" do
  response.headers["Allow"] = "GET, POST, OPTIONS"
  response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, X-User-Email, X-Auth-Token"
  response.headers["Access-Control-Allow-Origin"] = "*"
  response.headers["X-Content-Security-Policy"] = "frame-ancestors https://*.atlassian.net";
  response.headers["Content-Security-Policy"] = "frame-ancestors https://*.atlassian.net";
  200
end

use Rack::Session::Cookie, :secret => COOKIE_SECRET.to_s()
set :protection, :except => :frame_options
set :public_folder, 'public'
set :static_cache_control, [:public, :max_age => 2678400]
Octokit.default_media_type = "application/vnd.github.machine-man-preview+json"

# Sinatra Endpoints
# -----------------
client = Octokit::Client.new

post '/addon_installed' do
  begin
    request.body.rewind
    request_payload = JSON.parse request.body.read
    ATLASSIAN_CLIENT_KEY = request_payload["clientKey"]
    ATLASSIAN_SHARED_SECRET = request_payload["sharedSecret"]
    puts ATLASSIAN_SHARED_SECRET  # TODO: secure management of shared secrets for security contexts

    status 200
    body ''
  rescue
    status 404
    body ''
  end
end


post '/addon_uninstalled' do
  status 200
  body ''
end


get '/callback' do
  session_code = params[:code]
  result = Octokit.exchange_code_for_token(session_code, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET)
  session[:access_token] = result[:access_token]

  return erb :close
end

# GitHub will include `installation_id` after installing the App
get '/post_app_install' do
  # Send the user back to JIRA
  if !session[:referrer].nil? && session[:referrer] != ''
    redirect session[:referrer]
  end

  return erb :close
end

# Entry point for JIRA Add-on.
# JIRA passes in a number of URL parameters https://goo.gl/zyGLiF
get '/main_entry' do
  # Used in templates to load JS and CSS
  session[:fqdn] = params[:xdm_e].nil? ? "" : params[:xdm_e]
  # JIRA ID is passed as context-parameters.
  # Referenced in atlassian-connect.json
  session[:addon_key] = params.fetch("xdm_deprecated_addon_key_do_not_use")
  session[:jira_issue] = params.fetch("issueKey", $default_branch_name)
  puts ATLASSIAN_SHARED_SECRET
  session[:summary] = get_issue_info(session[:jira_issue], session[:fqdn], session[:addon_key], ATLASSIAN_SHARED_SECRET)
  redirect to('/')
end

# Main application logic
get '/' do
  if session[:jira_issue].nil?
    session[:jira_issue] = $default_branch_name
  end

  # Need user's OAuth token to lookup installation id
  if !authenticated?
    @url = client.authorize_url(GITHUB_CLIENT_ID)
    @icon_svg = Octicons::Octicon.new("mark-github").to_svg
    return erb :login
  end

  if !set_repo?
    @name_list = get_user_repositories(session[:access_token])
    if @name_list.length == 0
      @app_url = GITHUB_APP_URL
      return erb :install_app
    end
    session[:name_list] = @name_list
    # Show end-user a list of all repositories they can create a branch in
    redirect to('/select_repo')
  else
    unless set_branch?
      session[:branch_name] = issue_to_branch_name(session[:jira_issue])
    end
    if branch_exists?(session[:branch_name])  # TODO: need exact match instead of prefix
      @icon_svg = Octicons::Octicon.new("git-branch").to_svg
      return erb :link_to_branch
    end

    # Authenticated but not viewing JIRA ticket
    if session[:jira_issue] == $default_branch_name
      return erb :thank_you
    end

    @repo_name = session[:repo_name]
    @default_branch_suffix = sanitize_branch_name(session[:summary])
    @icon_svg = Octicons::Octicon.new("git-branch").to_svg
    return erb :create_branch
  end
end

#
post '/payload' do
  github_event = request.env['HTTP_X_GITHUB_EVENT']
  webhook_data = JSON.parse(request.body.read)

  if github_event == "installation" || github_event == "installation_repositories"
    puts "installation event"
  else
    puts "New event #{github_event}"
  end
end

# Clear all session information
get '/logout' do
  session.delete(:repo_name)
  session.delete(:branch_name)
  session.delete(:name_list)
  session.delete(:app_token)
  session.delete(:access_token)
  redirect to('/')
end

# Create a branch for the selected repository if it doesn't already exist.
get '/create_branch' do
  if !set_repo? || !set_branch? || branch_exists?(session[:branch_name])
    redirect to('/')
  end
  app_token = get_app_token(session[:repo_name][:installation_id])
  client = Octokit::Client.new(:access_token => app_token )

  repo_name = session[:repo_name][:full_name]
  branch_name = session[:branch_name]
  unless params[:suffix].nil?
    suffix = params[:suffix]
    branch_name = "#{branch_name}-#{suffix}"
  end
  session[:branch_name] = branch_name

  begin
    # Look up default branch
    repo_data = client.repository(repo_name)
    default_branch = repo_data[:default_branch]

    # Create branch at tip of the default branch
    sha = client.ref(repo_name, "heads/#{default_branch}")[:object][:sha]
    ref = client.create_ref(repo_name, "heads/#{branch_name}", sha.to_s)

  rescue
    puts "Failed to create branch #{branch_name}"
    redirect to('/logout')
  end
  redirect to('/')
end

# List all repos
get '/select_repo' do
  if !authenticated? || !session.key?(:name_list)
    redirect to('/')
  end
  @name_list = session[:name_list]
  @icon_svg = Octicons::Octicon.new("repo").to_svg
  return erb :show_repos
end

# Store which Repository the user selected
get '/add_repo' do
  if !authenticated?
    redirect to('/')
  end

  input_repo = params[:repo_name]

  # need to check if repo is in the list
  session[:name_list].each do |repository_name|
    if input_repo == repository_name[:full_name]
      session[:repo_name] = repository_name
      session[:branch_name] = issue_to_branch_name(session[:jira_issue])
      break
    end
  end
  redirect to('/')
end


# JIRA session methods
# -----------------

# Returns true if the user completed OAuth2 handshake and has a token
def authenticated?
  !session[:access_token].nil? && session[:access_token] != ''
end

# Returns whether a branch name has been set for this JIRA issue
def set_branch?
  !session[:branch_name].nil? && session[:branch_name] != ''
end

# Returns whether the user selected a repository to map to this JIRA project
def set_repo?
  !session[:repo_name].nil? && session[:repo_name] != ''
end

# Returns branch name with JIRA issue prefix if one exists, otherwise JIRA issue key
def issue_to_branch_name(jira_issue)
  app_token = get_app_token(session[:repo_name][:installation_id])
  client = Octokit::Client.new(:access_token => app_token)

  repo_name = session[:repo_name][:full_name]
  branch_name = jira_issue

  begin
    # Does this branch exist
    ref_resp = client.ref(repo_name, "heads/#{branch_name}")
  rescue => e
    puts e
    return branch_name
  end

  branch_name = ref_resp[0].ref.split("refs/heads/")[-1]
  branch_name
end


# Returns whether a branch for this issue already exists
def branch_exists?(branch_name_query)

  app_token = get_app_token(session[:repo_name][:installation_id])
  client = Octokit::Client.new(:access_token => app_token)

  repo_name = session[:repo_name][:full_name]
  branch_name = branch_name_query

  begin
    # Does this branch exist
    sha = client.ref(repo_name, "heads/#{branch_name}")
  rescue
    return false
  end
  return true
end

def get_event_session_id
  if session[:user_session_id].nil? || session[:user_session_id] == '' 
    session[:user_session_id] = SecureRandom.uuid()
    puts "Created session id #{session[:user_session_id]}"
  end
  session[:user_session_id]
end

# GitHub Apps helper methods
# -----------------

def get_jwt
  private_pem = GITHUB_APP_KEY
  private_key = OpenSSL::PKey::RSA.new(private_pem)

  payload = {
    # issued at time
    iat: Time.now.to_i,
    # JWT expiration time (10 minute maximum)
    exp: 5.minutes.from_now.to_i,
    # Integration's GitHub identifier
    iss: GITHUB_APP_ID
  }

  JWT.encode(payload, private_key, "RS256")
end

def get_user_installations(access_token)
  url = "https://api.github.com/user/installations"
  headers = {
    authorization: "token #{access_token}",
    accept: "application/vnd.github.machine-man-preview+json"
  }
  # headers = {
  #   accept: "application/vnd.github.machine-man-preview+json"
  # }

  begin
    response = RestClient.get(url,headers)
  rescue => e
    puts e.response.body
  end
  json_response = JSON.parse(response)

  installation_id = []
  if json_response["total_count"] > 0
    json_response["installations"].each do |installation|
      installation_id.push(installation["id"])
    end
  end
  installation_id
end


def get_user_repositories(access_token)
  repository_list = []
  ids = get_user_installations(access_token)
  ids.each do |id|
    url ="https://api.github.com/user/installations/#{id}/repositories"
    headers = {
      authorization: "token #{access_token}",
      accept: "application/vnd.github.machine-man-preview+json"
    }
    begin
      response = RestClient.get(url,headers)
      json_response = JSON.parse(response)

      if json_response["total_count"] > 0
        json_response["repositories"].each do |repo|
          repository_list.push({
            full_name: repo["full_name"],
            installation_id: id
          })
        end
      end
    rescue => error
      puts "User Repo Error : #{error}"
    end
  end
  repository_list
end

def get_app_token(installation_id)
  token_url = "https://api.github.com/installations/#{installation_id}/access_tokens"
  jwt = get_jwt
  return_val = ""
  headers = {
    authorization: "Bearer #{jwt}",
    accept: "application/vnd.github.machine-man-preview+json"
  }
  begin
    response = RestClient.post(token_url,{},headers)
    app_token = JSON.parse(response)
    return_val = app_token["token"]
  rescue => error
    puts "app_access_token #{error}"
  end
  return_val
end

def sanitize_branch_name(branch_name)
  branch_name.gsub! "..", ""
  branch_name.gsub! ".lock", ""
  branch_name.gsub! /[\/~^: \[\]\\]/, "-"  # replaces /,~,^,:,[,],\, and whitespaces with -
  branch_name
end

def get_issue_info(issue_key, base_url, issuer, shared_secret)
  url = "#{base_url}/rest/api/latest/search?fields=summary&jql=issueKey=#{issue_key}"
  http_method = 'GET'
  claim = Atlassian::Jwt.build_claims(issuer,url,http_method)
  jwt = JWT.encode(claim,shared_secret)
  response = HTTParty.get("#{url}&jwt=#{jwt}")
  response.parsed_response["issues"][0]["fields"]["summary"]
end
