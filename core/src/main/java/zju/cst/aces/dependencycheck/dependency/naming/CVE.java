package zju.cst.aces.dependencycheck.dependency.naming;

import com.alibaba.fastjson2.annotation.JSONField;

import java.util.List;

public class CVE{
	@JSONField
	private String cve_id;
	@JSONField
	private List<String> cpes;
	@JSONField
	private double cvss2;
	@JSONField
	private String cveDescription;
	@JSONField
	private List<CVEPatchesItem> patches;
	@JSONField
	private String cvss2String;
	@JSONField
	private double cvss3;
	@JSONField
	private String cvss3String;
	@JSONField
	private List<String> cwes;

	public void setCveId(String cveId){
		this.cve_id = cveId;
	}

	public String getCveId(){
		return cve_id;
	}

	public void setCpes(List<String> cpes){
		this.cpes = cpes;
	}

	public List<String> getCpes(){
		return cpes;
	}

	public void setCvss2(double cvss2){
		this.cvss2 = cvss2;
	}

	public double getCvss2(){
		return cvss2;
	}

	public void setCveDescription(String cveDescription){
		this.cveDescription = cveDescription;
	}

	public String getCveDescription(){
		return cveDescription;
	}

	public void setPatches(List<CVEPatchesItem> patches){
		this.patches = patches;
	}

	public List<CVEPatchesItem> getPatches(){
		return patches;
	}

	public void setCvss2String(String cvss2String){
		this.cvss2String = cvss2String;
	}

	public String getCvss2String(){
		return cvss2String;
	}

	public void setCvss3(double cvss3){
		this.cvss3 = cvss3;
	}

	public double getCvss3(){
		return cvss3;
	}

	public void setCvss3String(String cvss3String){
		this.cvss3String = cvss3String;
	}

	public String getCvss3String(){
		return cvss3String;
	}

	public void setCwes(List<String> cwes){
		this.cwes = cwes;
	}

	public List<String> getCwes(){
		return cwes;
	}
}