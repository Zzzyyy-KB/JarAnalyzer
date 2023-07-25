package zju.cst.aces.dependencycheck.dependency.naming;

import com.alibaba.fastjson2.annotation.JSONField;

import java.util.List;

public class CVEFilesItem {
	@JSONField
	private String path;
	@JSONField
	private List<CVEFunctionsItem> functions;

	public void setPath(String path){
		this.path = path;
	}

	public String getPath(){
		return path;
	}

	public void setFunctions(List<CVEFunctionsItem> functions){
		this.functions = functions;
	}

	public List<CVEFunctionsItem> getFunctions(){
		return functions;
	}
}