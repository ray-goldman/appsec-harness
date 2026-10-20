class ToolsController < ApplicationController
  def convert
    system("convert", "--", params[:file].to_s, "out.png")
  end

  def calc
    render plain: Calculator.evaluate(params[:expr].to_s)
  end

  def bio
    @bio = helpers.sanitize(params[:bio].to_s)
  end
end
