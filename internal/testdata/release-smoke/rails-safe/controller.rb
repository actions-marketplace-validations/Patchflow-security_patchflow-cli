# Rails safe fixture: parameterized ActiveRecord queries.
# The safe pattern "where(" should suppress PF-RAILS-SQLI-003 -IP false positives
# on parameterized ORM queries.
class UsersController < ApplicationController
  def index
    # SAFE: parameterized ActiveRecord where with hash syntax
    @users = User.where(name: params[:name])
    render json: @users
  end

  def show
    # SAFE: parameterized ActiveRecord find_by
    @user = User.find_by(id: params[:id])
    render json: @user
  end
end
