package zju.cst.aces.dependencycheck.dependency.naming;

import com.alibaba.fastjson2.annotation.JSONField;

import java.util.List;

public class CVEPatchesItem {
	@JSONField
	private String owner;
	@JSONField
	private String repo;
	@JSONField
	private List<CVEFilesItem> files;
	@JSONField
	private String commit_message;
	@JSONField
	private String diff_file;
	@JSONField
	private String url;

	public void setOwner(String owner){
		this.owner = owner;
	}

	public String getOwner(){
		return owner;
	}

	public void setRepo(String repo){
		this.repo = repo;
	}

	public String getRepo(){
		return repo;
	}

	public void setFiles(List<CVEFilesItem> files){
		this.files = files;
	}

	public List<CVEFilesItem> getFiles(){
		return files;
	}

	public void setcommit_message(String commitMessage){
		this.commit_message = commitMessage;
	}

	public String getcommit_message(){
		return commit_message;
	}

	public void setDiffFile(String diffFile){
		this.diff_file = diffFile;
	}

	public String getDiffFile(){
		return diff_file;
	}

	public void setUrl(String url){
		this.url = url;
	}

	public String getUrl(){
		return url;
	}
}