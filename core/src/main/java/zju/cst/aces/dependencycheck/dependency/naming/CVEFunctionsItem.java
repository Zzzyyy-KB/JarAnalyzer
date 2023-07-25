package zju.cst.aces.dependencycheck.dependency.naming;

import com.alibaba.fastjson2.annotation.JSONField;

public class CVEFunctionsItem {
	@JSONField
	private String a_func;
	@JSONField
	private String b_func;
	@JSONField
	private int line;
	@JSONField
	private String function_name;

	public void setAFunc(String aFunc){
		this.a_func = aFunc;
	}

	public String getAFunc(){
		return a_func;
	}

	public void setBFunc(String bFunc){
		this.b_func = bFunc;
	}

	public String getBFunc(){
		return b_func;
	}

	public void setLine(int line){
		this.line = line;
	}

	public int getLine(){
		return line;
	}

	public void setfunction_name(String functionName){
		this.function_name = functionName;
	}

	public String getfunction_name(){
		return function_name;
	}
}
