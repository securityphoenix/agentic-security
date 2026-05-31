class UsersController < ApplicationController
  def index
    @users = User.where('name = ?', params[:name])
    render json: @users
  end
end
