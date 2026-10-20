class ToolsController < ApplicationController
  def convert
    system("convert #{params[:file]} out.png")
  end

  def calc
    render plain: eval(params[:expr])
  end

  def bio
    @bio = params[:bio].html_safe
  end
end
