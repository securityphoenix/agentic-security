class UsersController < ApplicationController
  ALLOWED_ACTIONS = %w[promote demote suspend].freeze

  def update
    user.update(user_params)                         # safe: strong params
  end

  def dispatch_safe
    action = ALLOWED_ACTIONS.include?(params[:action]) ? params[:action].to_sym : :default
    user.send(action)                                # safe: whitelist
  end

  def cfg
    YAML.safe_load(params[:config])                  # safe yaml
  end

  private
  def user_params
    params.require(:user).permit(:name, :email)
  end
end
