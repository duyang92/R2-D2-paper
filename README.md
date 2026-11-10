<h1 align="center">
  <br>
  R2-D2
  <br>
</h1>

<h4 align="center">R2-D2: A Runtime-Reconfigurable In-Switch Defense System Against Dynamic Volumetric DDoS Attacks</h4>

<p align="center">
  <a href="#-Deployment-Environment">Deployment Environment</a> •
  <a href="#-Code-Overview">Code Overview</a> •
  <a href="#-task-interface">Task Interface</a> •
  <a href="#-Get-Started">Get Started</a>
</p>

---

## ⚙️ Deployment Environment

- **Switch**: Tofino1  
- **SDE Version**: bf-sde-9.2.0  
- **Python**: 2.7.13  

---

## 📦 Code Overview
### 📁 Data Plane
- **p4_src/** – P4 implementation of R2-D2’s data plane logic.
### 📁 Control Plane
- **control_src/** – Control plane logic for runtime defense task management, which implements runtime deployment of defense tasks and other functions. Secondary development of the control plane can be carried out on this basis
  - **task_interface/payload.json**: Configuration for defense tasks (as an interface, user-modifiable).
  - **src/Data.py**: Loads and parses payload.json.
  - **src/sketch.py**: Manages Sketch memory allocation and release.
  - **src/generate.py**: Runtime reconfiguration of defense tasks, using gRPC to implement runtime reconfiguration tasks, and showing the control commands for adding or reclaiming corresponding defense tasks for reference (no need to execute manually)
  - **src/run_cli.py**: Executes CLI commands via Python.
  - **src/main_example.py**: Example of runtime deployment and deletion of defense tasks.

## 🧩 Task Interface
The **payload.json** file stores parameters for configuring defense tasks. It can be modified manually or through secondary development of the control logic.
### 🔑 Fields
- switch_ports
  - in: Ports connected to the internal network.
  - out: Ports connected to the external network.
- payload: Packet match rules per defense task.
  - Example: ["0x06", 2, 2, 1] – Matches TCP SYN packets.
  - Example: [0, 0, 53, 65535, 1] – Matches DNS queries to port 53.
- defense_scheme: The defense approach to which the defense task belongs.
- task_id: Unique ID of the defense task.
- use_sketch: Indicates whether to use a Sketch.
- sketch_id: Sketch ID of the defense task (using the same Sketch ID for multiple tasks can achieve memory reuse).
- sketch_row: Number of Sketch rows used.
- defense_stage: Defense layer (e.g., network/transport, application).
- in_or_out
  - 0: Only matches external-to-internal traffic.
  - 1: First rule matches internal-to-external; second matches external-to-internal.
- meter_id: Meter resource used for detection and rate-limiting.
- param: Sketch update value.
- result_start, result_end: Drop result range for memory updates.
- token: Whether to use meter-based rate limiting.
- color_start, color_end: Drop thresholds by packet color.
- spec_cir_pps, etc.: Token bucket meter parameters (CIR, PIR, etc.).


## 🚀 Get Started

### 🛠️ Step 1: Clone and Enter the Repository

```bash
cd R2-D2
```

### 🧱 Step 2: Compile and Load the Data Plane
```bash
# Compile R2-D2
$SDE/p4_build.sh ./p4_src/R2_D2.p4
# Run R2-D2
$SDE/run_switchd.sh -p R2_D2
```
> 🔔 Ensure $SDE and $SDE_INSTALL environment variables are correctly set.

### 📡 Step 3: Launch the Control Plane
```bash
python ./control_src/src/main_example.py
```
> This script demonstrates dynamic deployment/removal of defense tasks via the control plane.


