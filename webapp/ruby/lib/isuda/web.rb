require 'digest/sha1'
require 'json'
require 'net/http'
require 'uri'

require 'erubis'
require 'mysql2'
require 'mysql2-cs-bind'
require 'rack/utils'
require 'sinatra/base'
require 'tilt/erubis'
require 'newrelic_rpm'
require 'redis'

module Isuda
  class Web < ::Sinatra::Base
    enable :protection
    enable :sessions

    set :erb, escape_html: true
    set :public_folder, File.expand_path('../../../../public', __FILE__)

    set :db_user, ENV['ISUDA_DB_USER'] || 'root'
    set :db_password, ENV['ISUDA_DB_PASSWORD'] || ''
    set :dsn, ENV['ISUDA_DSN'] || 'dbi:mysql:db=isuda'

    set :isutar_db_user, ENV['ISUTAR_DB_USER'] || 'root'
    set :isutar_db_password, ENV['ISUTAR_DB_PASSWORD'] || ''
    set :isutar_dsn, ENV['ISUTAR_DSN'] || 'dbi:mysql:db=isutar'

    set :session_secret, 'tonymoris'
    set :isupam_origin, ENV['ISUPAM_ORIGIN'] || 'http://localhost:5050'
    set :isuda_origin, ENV['ISUDA_ORIGIN'] || 'http://localhost:5000'

    configure :development do
      require 'sinatra/reloader'

      register Sinatra::Reloader
    end

    set(:set_name) do |value|
      condition {
        user_name = session[:user_name]
        if user_name
          user = redis.get("user_#{name}")
          halt(403) unless user_name

          @user_id = user[:id]
          @user_name = user[:name]
        end
      }
    end

    set(:authenticate) do |value|
      condition {
        halt(403) unless @user_id
      }
    end

    helpers do
      # @return [Mysql2::Client]
      def db
        Thread.current[:db] ||=
          begin
            _, _, attrs_part = settings.dsn.split(':', 3)
            attrs = Hash[attrs_part.split(';').map {|part| part.split('=', 2) }]
            mysql = Mysql2::Client.new(
              username: settings.db_user,
              password: settings.db_password,
              database: attrs['db'],
              encoding: 'utf8mb4',
              init_command: %|SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'|,
            )
            mysql.query_options.update(symbolize_keys: true)
            mysql
          end
      end

      # @return [Mysql2::Client]
      def isutar_db
        Thread.current[:isutar_db] ||=
            begin
              _, _, attrs_part = settings.isutar_dsn.split(':', 3)
              attrs = Hash[attrs_part.split(';').map {|part| part.split('=', 2) }]
              mysql = Mysql2::Client.new(
                  username: settings.isutar_db_user,
                  password: settings.isutar_db_password,
                  database: attrs['db'],
                  encoding: 'utf8mb4',
                  init_command: %|SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'|,
              )
              mysql.query_options.update(symbolize_keys: true)
              mysql
            end
      end

      def redis
        Thread.current[:redis] ||= Redis.new
      end

      def cache(key) # with block
        value = redis.get(key)
        if value.nil?
          value = yield
        end
        value
      end

      def register(name, pw)
        chars = [*'A'..'~']
        salt = 1.upto(20).map { chars.sample }.join('')
        salted_password = encode_with_salt(password: pw, salt: salt)
        db.xquery(%|
          INSERT INTO user (name, salt, password, created_at)
          VALUES (?, ?, ?, NOW())
        |, name, salt, salted_password)
        redis.set("user_#{name}", { id: db.last_id, salt: salt, password: salted_password }.to_json)
        db.last_id
      end

      def encode_with_salt(password: , salt: )
        Digest::SHA1.hexdigest(salt + password)
      end

      def is_spam_content(content)
        isupam_uri = URI(settings.isupam_origin)
        res = Net::HTTP.post_form(isupam_uri, 'content' => content)
        validation = JSON.parse(res.body)
        validation['valid']
        ! validation['valid']
      end

      def is_spam_keyword(keyword)
        cache("is_spam_keyword/#{keyword}") do
          is_spam_content(keyword)
        end
      end

      def load_keywords
        db.xquery(%| select * from entry order by character_length(keyword) desc |).map do |x|
          x[:keyword]
        end
      end

      def htmlify(content, keywords = load_keywords)
        pattern = keywords.map {|k| Regexp.escape(k) }.join('|')

        cache(Digest::SHA1.hexdigest(content + "\0" + pattern)) do
          kw2hash = {}
          hashed_content = content.gsub(/(#{pattern})/) {|m|
            matched_keyword = $1
            "isuda_#{Digest::SHA1.hexdigest(matched_keyword)}".tap do |hash|
              kw2hash[matched_keyword] = hash
            end
          }
          escaped_content = Rack::Utils.escape_html(hashed_content)
          kw2hash.each do |(keyword, hash)|
            keyword_url = url("/keyword/#{Rack::Utils.escape_path(keyword)}")
            anchor = '<a href="%s">%s</a>' % [keyword_url, Rack::Utils.escape_html(keyword)]
            escaped_content.gsub!(hash, anchor)
          end
          escaped_content.gsub(/\n/, "<br />\n")
        end
      end

      def uri_escape(str)
        Rack::Utils.escape_path(str)
      end

      def load_stars(keyword)
        isutar_db.xquery(%| select * from star where keyword = ? |, keyword).to_a
      end

      def load_entries(page, per_page)
        entries = db.xquery(%|
        SELECT * FROM entry
        ORDER BY updated_at DESC
        LIMIT #{per_page}
        OFFSET #{per_page * (page - 1)}
                            |)

        keywords = load_keywords
        entries.each do |entry|
          entry[:html] = htmlify(entry[:description], keywords)
          entry[:stars] = load_stars(entry[:keyword])
        end
        entries
      end

      def redirect_found(path)
        redirect(path, 302)
      end

      def total_entries
        redis.get('total_entries')
      end

      def update_total_entries
        redis.set('total_entries', db.xquery(%| SELECT count(*) AS total_entries FROM entry |).first[:total_entries].to_i)
      end
    end

    get '/initialize' do
      redis.flushall

      db.xquery(%| DELETE FROM entry WHERE id > 7101 |)
      isutar_db.xquery('TRUNCATE star')

      db.xquery(%| select id, name, password, salt from user |).each do |user|
        redis.set("user_#{user[:name]}", { id: user[:id], salt: user[:salt], password: user[:password] }.to_json)
      end
      update_total_entries

      load_entries(1, 10)

      content_type :json
      JSON.generate(result: 'ok')
    end

    get '/', set_name: true do
      per_page = 10
      page = (params[:page] || 1).to_i

      entries = load_entries(page, per_page)

      last_page = (total_entries.to_f / per_page.to_f).ceil
      from = [1, page - 5].max
      to = [last_page, page + 5].min
      pages = [*from..to]

      locals = {
        entries: entries,
        page: page,
        pages: pages,
        last_page: last_page,
      }
      erb :index, locals: locals
    end

    get '/robots.txt' do
      halt(404)
    end

    get '/register', set_name: true do
      erb :register
    end

    post '/register' do
      name = params[:name] || ''
      pw   = params[:password] || ''
      halt(400) if (name == '') || (pw == '')

      user_id = register(name, pw)
      session[:user_id] = user_id
      session[:user_name] = name

      redirect_found '/'
    end

    get '/login', set_name: true do
      locals = {
        action: 'login',
      }
      erb :authenticate, locals: locals
    end

    post '/login' do
      name = params[:name]
      user_cache = redis.get("user_#{name}")
      halt(403) unless user_cache
      user = JSON.parse(user_cache, symbolize_names: true)
      halt(403) unless user[:password] == encode_with_salt(password: params[:password], salt: user[:salt])

      session[:user_id] = user[:id]
      session[:user_name] = user[:name]

      redirect_found '/'
    end

    get '/logout' do
      session[:user_id] = nil
      redirect_found '/'
    end

    post '/keyword', set_name: true, authenticate: true do
      keyword = params[:keyword] || ''
      halt(400) if keyword == ''
      description = params[:description]
      halt(400) if is_spam_content(description) || is_spam_keyword(keyword)

      bound = [@user_id, keyword, description] * 2
      db.xquery(%|
        INSERT INTO entry (author_id, keyword, description, created_at, updated_at)
        VALUES (?, ?, ?, NOW(), NOW())
        ON DUPLICATE KEY UPDATE
        author_id = ?, keyword = ?, description = ?, updated_at = NOW()
      |, *bound)
      update_total_entries

      redirect_found '/'
    end

    get '/keyword/:keyword', set_name: true do
      keyword = params[:keyword] or halt(400)

      cached_stars = redis.get(keyword)
      halt(404) unless cached_stars

      entry = db.xquery(%| select * from entry where keyword = ? |, keyword).first
      entry[:html] = htmlify(entry[:description])
      entry[:stars] = JSON.parse(cached_stars)

      locals = {
        entry: entry,
      }
      erb :keyword, locals: locals
    end

    post '/keyword/:keyword', set_name: true, authenticate: true do
      keyword = params[:keyword] or halt(400)
      is_delete = params[:delete] or halt(400)

      unless db.xquery(%| SELECT * FROM entry WHERE keyword = ? |, keyword).first
        halt(404)
      end

      db.xquery(%| DELETE FROM entry WHERE keyword = ? |, keyword)
      redis.del(keyword)

      redirect_found '/'
    end

    # ================================
    # The isutar app
    # ================================

    get '/stars' do
      keyword = params[:keyword] || ''
      stars = isutar_db.xquery(%| select * from star where keyword = ? |, keyword).to_a

      content_type :json
      JSON.generate(stars: stars)
    end

    post '/stars' do
      keyword = params[:keyword]

      # check if the keyword exists or not
      db.xquery(%| select id from entry where keyword = ? |, keyword).first or halt(404)

      user_name = params[:user]
      isutar_db.xquery(%|
        INSERT INTO star (keyword, user_name, created_at)
        VALUES (?, ?, NOW())
      |, keyword, user_name)

      content_type :json
      JSON.generate(result: 'ok')
    end
  end
end
