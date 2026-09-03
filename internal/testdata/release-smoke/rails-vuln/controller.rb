# Rails vulnerable fixture: raw SQL string interpolation.
# PF-RAILS-SQLI-003 should fire on the string interpolation in the query method.
class UsersController < ApplicationController
  def search
    # VULNERABLE: string interpolation in raw SQL
    @users = User.where("name LIKE '%#{params[:q]}%'")
    render json: @users
  end

  def redirect_to_url
    # VULNERABLE: open redirect
    redirect_to params[:url]
  end
end
