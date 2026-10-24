import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as THREE from 'three';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import {
  Shield,
  Layers,
  Camera,
  Maximize2,
  Minimize2,
  ChevronDown,
  ChevronUp,
  RotateCw,
  Play,
  Pause,
  AlertTriangle,
  Radio,
  Crosshair,
  Volume2,
  VolumeX,
} from 'lucide-react';
import { ScanRecordDoc } from '../lib/firebase';

interface CyberMatrix3DProps {
  scans?: ScanRecordDoc[];
  recentScan?: {
    target: string;
    riskScore: number;
    verdict: string;
    scanType: string;
  } | null;
  onCloseFullView?: () => void;
  isFullView?: boolean;
}

// Pre-allocated scratch objects to ensure 0 GC allocations inside the 60fps render loop
const _vec3 = new THREE.Vector3();
const _targetPos = new THREE.Vector3();
const _color = new THREE.Color();

// Procedural grid texture generator for the tactical floor (Zero 404 dependencies)
function createTacticalGridTexture(): THREE.CanvasTexture {
  const canvas = document.createElement('canvas');
  canvas.width = 1024;
  canvas.height = 1024;
  const ctx = canvas.getContext('2d')!;

  ctx.fillStyle = '#030712';
  ctx.fillRect(0, 0, 1024, 1024);

  // Concentric radar range rings
  ctx.strokeStyle = '#064e3b';
  ctx.lineWidth = 2;
  const center = 512;
  const radii = [120, 240, 360, 480];
  radii.forEach((r) => {
    ctx.beginPath();
    ctx.arc(center, center, r, 0, Math.PI * 2);
    ctx.stroke();
  });

  // Crosshairs & azimuth marks
  ctx.strokeStyle = '#047857';
  ctx.lineWidth = 1;
  ctx.setLineDash([8, 8]);
  ctx.beginPath();
  ctx.moveTo(512, 20);
  ctx.lineTo(512, 1004);
  ctx.moveTo(20, 512);
  ctx.lineTo(1004, 512);
  ctx.stroke();
  ctx.setLineDash([]);

  // Hexagonal grid cells overlay
  ctx.strokeStyle = '#022c22';
  ctx.lineWidth = 1;
  const size = 32;
  const h = size * Math.sqrt(3);
  for (let y = 0; y < 1024 + h; y += h) {
    for (let x = 0; x < 1024 + size * 3; x += size * 3) {
      drawHex(ctx, x, y, size);
      drawHex(ctx, x + size * 1.5, y + h / 2, size);
    }
  }

  // Range text labels
  ctx.fillStyle = '#10b981';
  ctx.font = 'bold 16px monospace';
  ctx.fillText('10KM PERIMETER', 520, 512 - 125);
  ctx.fillText('25KM DEFENSE ZONE', 520, 512 - 245);
  ctx.fillText('50KM THREAT HORIZON', 520, 512 - 365);

  const texture = new THREE.CanvasTexture(canvas);
  texture.wrapS = THREE.ClampToEdgeWrapping;
  texture.wrapT = THREE.ClampToEdgeWrapping;
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function drawHex(ctx: CanvasRenderingContext2D, x: number, y: number, r: number) {
  ctx.beginPath();
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 3) * i;
    const hx = x + r * Math.cos(angle);
    const hy = y + r * Math.sin(angle);
    if (i === 0) ctx.moveTo(hx, hy);
    else ctx.lineTo(hx, hy);
  }
  ctx.closePath();
  ctx.stroke();
}

// Procedural contact shadow radial map
function createContactShadowTexture(): THREE.CanvasTexture {
  const canvas = document.createElement('canvas');
  canvas.width = 512;
  canvas.height = 512;
  const ctx = canvas.getContext('2d')!;

  const gradient = ctx.createRadialGradient(256, 256, 10, 256, 256, 240);
  gradient.addColorStop(0, 'rgba(0, 0, 0, 0.85)');
  gradient.addColorStop(0.35, 'rgba(0, 0, 0, 0.45)');
  gradient.addColorStop(0.7, 'rgba(0, 0, 0, 0.15)');
  gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');

  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 512, 512);

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

export const CyberMatrix3D: React.FC<CyberMatrix3DProps> = ({
  scans = [],
  recentScan,
  onCloseFullView,
  isFullView = false,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Collapsible bottom dock & interactive settings
  const [controlsCollapsed, setControlsCollapsed] = useState(false);
  const [explodedRatio, setExplodedRatio] = useState(0); // 0 = assembled, 1 = exploded
  const [autoRotate, setAutoRotate] = useState(true);
  const [activeTheme, setActiveTheme] = useState<'emerald' | 'cobalt' | 'amber' | 'crimson'>('emerald');
  const [activeCameraView, setActiveCameraView] = useState<'orbit' | 'radar' | 'core' | 'patrol'>('orbit');
  const [activeThreatSim, setActiveThreatSim] = useState<'idle' | 'phish' | 'dnsbl' | 'brute'>('idle');
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [hoveredSubsystem, setHoveredSubsystem] = useState<string | null>(null);

  // Audio Context for synthetic sci-fi hum and threat alerts (Zero MP3 files)
  const audioCtxRef = useRef<AudioContext | null>(null);
  const soundGainRef = useRef<GainNode | null>(null);

  // Mutable refs to pass UI state into the requestAnimationFrame loop without tearing down WebGL
  const explodedRatioRef = useRef(explodedRatio);
  explodedRatioRef.current = explodedRatio;

  const autoRotateRef = useRef(autoRotate);
  autoRotateRef.current = autoRotate;

  const activeThemeRef = useRef(activeTheme);
  activeThemeRef.current = activeTheme;

  const activeCameraViewRef = useRef(activeCameraView);
  activeCameraViewRef.current = activeCameraView;

  const activeThreatSimRef = useRef(activeThreatSim);
  activeThreatSimRef.current = activeThreatSim;

  // Initialize Web Audio oscillator for procedural telemetry pulse
  useEffect(() => {
    if (!soundEnabled) {
      if (audioCtxRef.current && audioCtxRef.current.state === 'running') {
        audioCtxRef.current.suspend();
      }
      return;
    }

    try {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (!audioCtxRef.current) {
        audioCtxRef.current = new AudioCtx();
        const gain = audioCtxRef.current.createGain();
        gain.gain.value = 0.04;
        gain.connect(audioCtxRef.current.destination);
        soundGainRef.current = gain;

        const osc = audioCtxRef.current.createOscillator();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(84, audioCtxRef.current.currentTime);
        osc.connect(gain);
        osc.start();
      } else if (audioCtxRef.current.state === 'suspended') {
        audioCtxRef.current.resume();
      }
    } catch {
      // Audio autoplay policy fallback
    }
  }, [soundEnabled]);

  // Main Three.js Lifecycle Mounted in Ref Container
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // 1. Software-WebGL Detection Guard (Three.js skill directive)
    const isSoftwareGl = (() => {
      const probeCanvas = document.createElement('canvas');
      const gl = probeCanvas.getContext('webgl2');
      if (!gl) return true;
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
      const gpu = String(gl.getParameter(param));
      gl.getExtension('WEBGL_lose_context')?.loseContext();
      return /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
    })();

    // 2. WebGL Renderer with ACES Filmic Tone Mapping & Color Management
    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || 560;

    const renderer = new THREE.WebGLRenderer({
      antialias: !isSoftwareGl,
      powerPreference: 'high-performance',
      alpha: false,
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.15;
    renderer.shadowMap.enabled = !isSoftwareGl;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;

    container.appendChild(renderer.domElement);

    // 3. Scene, Camera, Fog
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x020617);
    scene.fog = new THREE.FogExp2(0x020617, 0.024);

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(11, 7.5, 12);

    // 4. Studio Environment Lighting (RoomEnvironment via PMREMGenerator)
    const pmremGenerator = new THREE.PMREMGenerator(renderer);
    scene.environment = pmremGenerator.fromScene(new RoomEnvironment(), 0.04).texture;
    pmremGenerator.dispose();

    // 5. Studio Lighting Rig: Warm Key Light + Cool Hemisphere Fill + Accent Rims
    const hemiLight = new THREE.HemisphereLight(0x38bdf8, 0x020617, 0.95);
    scene.add(hemiLight);

    const keyLight = new THREE.DirectionalLight(0xffffff, 2.2);
    keyLight.position.set(8, 14, 6);
    keyLight.castShadow = !isSoftwareGl;
    if (keyLight.castShadow) {
      keyLight.shadow.mapSize.width = 1024;
      keyLight.shadow.mapSize.height = 1024;
      keyLight.shadow.camera.near = 1;
      keyLight.shadow.camera.far = 30;
      keyLight.shadow.camera.left = -8;
      keyLight.shadow.camera.right = 8;
      keyLight.shadow.camera.top = 8;
      keyLight.shadow.camera.bottom = -8;
      keyLight.shadow.bias = -0.0005;
      keyLight.shadow.normalBias = 0.02;
    }
    scene.add(keyLight);

    const rimLight1 = new THREE.DirectionalLight(0x10b981, 2.5);
    rimLight1.position.set(-9, 5, -8);
    scene.add(rimLight1);

    const rimLight2 = new THREE.PointLight(0x0ea5e9, 2.0, 15);
    rimLight2.position.set(0, 1.5, 0);
    scene.add(rimLight2);

    // 6. Camera Orbit Controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = !isSoftwareGl;
    controls.dampingFactor = 0.05;
    controls.maxPolarAngle = Math.PI / 2 - 0.03; // Never dip camera below ground
    controls.minDistance = 3.5;
    controls.maxDistance = 28;
    controls.target.set(0, 1.8, 0);

    // 7. Ground Plane with Procedural Tactical Grid Texture & Contact Shadow
    const gridTexture = createTacticalGridTexture();
    gridTexture.anisotropy = renderer.capabilities.getMaxAnisotropy();
    const groundGeo = new THREE.PlaneGeometry(36, 36);
    const groundMat = new THREE.MeshStandardMaterial({
      map: gridTexture,
      roughness: 0.75,
      metalness: 0.25,
    });
    groundMat.polygonOffset = true;
    groundMat.polygonOffsetFactor = 1;
    groundMat.polygonOffsetUnits = 1;

    const groundMesh = new THREE.Mesh(groundGeo, groundMat);
    groundMesh.rotation.x = -Math.PI / 2;
    groundMesh.receiveShadow = !isSoftwareGl;
    scene.add(groundMesh);

    // Soft Radial Contact Shadow Grounding
    const contactTexture = createContactShadowTexture();
    const shadowGeo = new THREE.PlaneGeometry(12, 12);
    const shadowMat = new THREE.MeshBasicMaterial({
      map: contactTexture,
      transparent: true,
      opacity: 0.65,
      depthWrite: false,
    });
    const contactShadow = new THREE.Mesh(shadowGeo, shadowMat);
    contactShadow.rotation.x = -Math.PI / 2;
    contactShadow.position.y = 0.02;
    scene.add(contactShadow);

    // =========================================================================
    // 8. PROCEDURAL 12-PART COMPOSITE 3D HERO SUBJECT: "AEGIS CYBER SHIELD CORE"
    // (Complies with 3-12 Part Composite Procedural Model Craft Directive)
    // =========================================================================
    const heroGroup = new THREE.Group();
    heroGroup.position.set(0, 0, 0); // Bottom-center flush on ground
    scene.add(heroGroup);

    // Sub-assemblies for exploded view separation along Y
    const baseAssembly = new THREE.Group();
    const coreAssembly = new THREE.Group();
    const ringAssembly = new THREE.Group();
    const canopyAssembly = new THREE.Group();
    const pylonAssembly = new THREE.Group();

    heroGroup.add(baseAssembly);
    heroGroup.add(coreAssembly);
    heroGroup.add(ringAssembly);
    heroGroup.add(canopyAssembly);
    heroGroup.add(pylonAssembly);

    // Dynamic Materials Library
    const primaryMetalMat = new THREE.MeshStandardMaterial({
      color: 0x1e293b,
      metalness: 0.94,
      roughness: 0.16,
    });

    const conduitDarkMat = new THREE.MeshStandardMaterial({
      color: 0x0f172a,
      metalness: 0.65,
      roughness: 0.55,
    });

    const glowAccentMat = new THREE.MeshStandardMaterial({
      color: 0x10b981,
      emissive: 0x059669,
      emissiveIntensity: 0.85,
      metalness: 0.2,
      roughness: 0.3,
    });

    const gimbalRingMat = new THREE.MeshStandardMaterial({
      color: 0x334155,
      metalness: 0.92,
      roughness: 0.18,
    });

    const innerCoreMat = new THREE.MeshStandardMaterial({
      color: 0x34d399,
      emissive: 0x10b981,
      emissiveIntensity: 1.2,
      roughness: 0.1,
      metalness: 0.1,
      transparent: true,
      opacity: 0.92,
    });

    // PART 1: Octagonal Beveled Heavy Pedestal
    const baseGeo = new THREE.CylinderGeometry(4.8, 5.4, 0.45, 8);
    const baseMesh = new THREE.Mesh(baseGeo, primaryMetalMat);
    baseMesh.position.y = 0.225;
    baseMesh.castShadow = !isSoftwareGl;
    baseMesh.receiveShadow = !isSoftwareGl;
    baseAssembly.add(baseMesh);

    // PART 2: Secondary Chamfered Platform with Heat Exchanger Slots
    const subBaseGeo = new THREE.CylinderGeometry(4.0, 4.4, 0.3, 8);
    const subBaseMesh = new THREE.Mesh(subBaseGeo, conduitDarkMat);
    subBaseMesh.position.y = 0.55;
    subBaseMesh.castShadow = !isSoftwareGl;
    baseAssembly.add(subBaseMesh);

    // PART 3: Optical Sensor Turret Well
    const wellGeo = new THREE.CylinderGeometry(2.8, 3.2, 0.35, 32);
    const wellMesh = new THREE.Mesh(wellGeo, primaryMetalMat);
    wellMesh.position.y = 0.85;
    baseAssembly.add(wellMesh);

    // PART 4: Central Reactor Crystal Chamber (Multi-Faceted Quantum Core)
    const crystalGeo = new THREE.OctahedronGeometry(1.15, 1);
    const crystalMesh = new THREE.Mesh(crystalGeo, innerCoreMat);
    crystalMesh.position.y = 1.85;
    coreAssembly.add(crystalMesh);

    // PART 5: Reactor Stanchion Armor Pillars (4 Verticals guarding crystal)
    const pillarGeo = new THREE.BoxGeometry(0.24, 1.4, 0.24);
    for (let i = 0; i < 4; i++) {
      const angle = (Math.PI / 2) * i;
      const pillar = new THREE.Mesh(pillarGeo, conduitDarkMat);
      pillar.position.set(Math.cos(angle) * 1.6, 1.85, Math.sin(angle) * 1.6);
      pillar.rotation.y = angle;
      coreAssembly.add(pillar);
    }

    // PART 6: Primary Gimbal Threat Interceptor Ring (Outer Torus)
    const ring1Geo = new THREE.TorusGeometry(3.3, 0.14, 20, 80);
    const ring1Mesh = new THREE.Mesh(ring1Geo, gimbalRingMat);
    ring1Mesh.position.y = 2.0;
    ringAssembly.add(ring1Mesh);

    // PART 7: Secondary Counter-Rotating Gimbal Ring (Inner Torus)
    const ring2Geo = new THREE.TorusGeometry(2.4, 0.11, 16, 64);
    const ring2Mesh = new THREE.Mesh(ring2Geo, glowAccentMat);
    ring2Mesh.position.y = 2.0;
    ringAssembly.add(ring2Mesh);

    // PART 8: Hex-Shield Force Field Dome (Transparent Energy Perimeter)
    const domeGeo = new THREE.SphereGeometry(3.6, 32, 16, 0, Math.PI * 2, 0, Math.PI * 0.5);
    const domeMat = new THREE.MeshPhysicalMaterial({
      color: 0x10b981,
      transparent: true,
      opacity: 0.18,
      roughness: 0.1,
      metalness: 0.1,
      transmission: isSoftwareGl ? 0 : 0.85,
      ior: 1.25,
      depthWrite: false,
      wireframe: false,
    });
    const domeMesh = new THREE.Mesh(domeGeo, domeMat);
    domeMesh.position.y = 0.7;
    canopyAssembly.add(domeMesh);

    // Dome Wireframe Rim
    const domeWireMat = new THREE.MeshBasicMaterial({
      color: 0x34d399,
      wireframe: true,
      transparent: true,
      opacity: 0.25,
      depthWrite: false,
    });
    const domeWireMesh = new THREE.Mesh(domeGeo, domeWireMat);
    domeWireMesh.position.y = 0.7;
    canopyAssembly.add(domeWireMesh);

    // PART 9: 4 Perimeter Sensor Monoliths / Radar Pylons
    const pylonBevelGeo = new THREE.CylinderGeometry(0.35, 0.55, 0.3, 6);
    const pylonStemGeo = new THREE.CylinderGeometry(0.18, 0.25, 1.8, 6);
    const pylonDishGeo = new THREE.ConeGeometry(0.45, 0.35, 12, 1, true);

    for (let i = 0; i < 4; i++) {
      const angle = (Math.PI / 2) * i + Math.PI / 4;
      const px = Math.cos(angle) * 7.5;
      const pz = Math.sin(angle) * 7.5;

      const pGroup = new THREE.Group();
      pGroup.position.set(px, 0, pz);

      const pBase = new THREE.Mesh(pylonBevelGeo, conduitDarkMat);
      pBase.position.y = 0.15;
      pGroup.add(pBase);

      const pStem = new THREE.Mesh(pylonStemGeo, primaryMetalMat);
      pStem.position.y = 1.05;
      pGroup.add(pStem);

      const pDish = new THREE.Mesh(pylonDishGeo, glowAccentMat);
      pDish.position.y = 2.05;
      pDish.rotation.x = Math.PI * 0.35;
      pDish.rotation.y = angle;
      pGroup.add(pDish);

      pylonAssembly.add(pGroup);
    }

    // PART 10: Rotating Tactical Radar Beam Cone
    const radarBeamGeo = new THREE.ConeGeometry(8.5, 0.05, 32, 1, false, 0, Math.PI * 0.35);
    const radarBeamMat = new THREE.MeshBasicMaterial({
      color: 0x10b981,
      transparent: true,
      opacity: 0.12,
      side: THREE.DoubleSide,
      depthWrite: false,
    });
    const radarBeam = new THREE.Mesh(radarBeamGeo, radarBeamMat);
    radarBeam.rotation.x = Math.PI / 2;
    radarBeam.position.y = 0.08;
    scene.add(radarBeam);

    // PART 11 & 12: Dynamic Threat Vectors & Attack Particles (Instanced)
    const threatBeams: THREE.Line[] = [];
    const threatCount = 6;
    for (let i = 0; i < threatCount; i++) {
      const lineGeo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(0, 0, 0),
        new THREE.Vector3(0, 0, 0),
      ]);
      const lineMat = new THREE.LineBasicMaterial({
        color: 0xef4444,
        transparent: true,
        opacity: 0,
      });
      const line = new THREE.Line(lineGeo, lineMat);
      scene.add(line);
      threatBeams.push(line);
    }

    // Threat Intercept Contact Sparks
    const sparkGeo = new THREE.SphereGeometry(0.18, 8, 8);
    const sparkMat = new THREE.MeshBasicMaterial({ color: 0xff3b30, depthWrite: false });
    const sparkMesh = new THREE.Mesh(sparkGeo, sparkMat);
    sparkMesh.visible = false;
    scene.add(sparkMesh);

    // Pre-warm shaders
    if (!isSoftwareGl) {
      renderer.compile(scene, camera);
    }

    // 9. Lossless 60fps Loop with Frame-Rate Independent Exponential Damping
    let frameId = 0;
    const clock = new THREE.Clock();

    function animate() {
      const dt = clock.getDelta();
      const elapsed = clock.getElapsedTime();

      // Exponential Damping for Exploded View Assembly Layers
      const targetExp = explodedRatioRef.current;
      const curYCore = THREE.MathUtils.damp(coreAssembly.position.y, targetExp * 1.8, 6.0, dt);
      const curYRing = THREE.MathUtils.damp(ringAssembly.position.y, targetExp * 3.2, 6.0, dt);
      const curYCanopy = THREE.MathUtils.damp(canopyAssembly.position.y, targetExp * 4.6, 6.0, dt);
      const curYPylon = THREE.MathUtils.damp(pylonAssembly.position.y, -targetExp * 0.4, 6.0, dt);

      coreAssembly.position.y = curYCore;
      ringAssembly.position.y = curYRing;
      canopyAssembly.position.y = curYCanopy;
      pylonAssembly.position.y = curYPylon;

      // Gimbal Rings Multi-Axis Rotation
      ring1Mesh.rotation.x = elapsed * 0.45;
      ring1Mesh.rotation.y = elapsed * 0.65;
      ring2Mesh.rotation.y = -elapsed * 0.85;
      ring2Mesh.rotation.z = elapsed * 0.35;

      // Crystal Pulsing Scale & Hover
      const pulseScale = 1.0 + Math.sin(elapsed * 3.5) * 0.08;
      crystalMesh.scale.set(pulseScale, pulseScale, pulseScale);
      crystalMesh.rotation.y = elapsed * 0.5;

      // Radar Sweep Rotation
      radarBeam.rotation.z = -elapsed * 0.9;

      // Auto-Orbit Camera if enabled and user isn't interacting
      if (autoRotateRef.current) {
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.8;
      } else {
        controls.autoRotate = false;
      }

      // Smooth Camera Transitions between View Presets
      const viewMode = activeCameraViewRef.current;
      if (viewMode === 'radar') {
        _targetPos.set(0, 22, 0.1);
        camera.position.lerp(_targetPos, 0.04);
        controls.target.lerp(_vec3.set(0, 0, 0), 0.05);
      } else if (viewMode === 'core') {
        _targetPos.set(4.5, 2.8, 4.5);
        camera.position.lerp(_targetPos, 0.04);
        controls.target.lerp(_vec3.set(0, 1.8, 0), 0.05);
      } else if (viewMode === 'patrol') {
        const px = Math.cos(elapsed * 0.2) * 14;
        const pz = Math.sin(elapsed * 0.2) * 14;
        _targetPos.set(px, 5.5, pz);
        camera.position.lerp(_targetPos, 0.03);
        controls.target.lerp(_vec3.set(0, 1.5, 0), 0.05);
      }

      controls.update();

      // Theme Colors Interpolation
      const theme = activeThemeRef.current;
      let targetHex = 0x10b981; // emerald
      if (theme === 'cobalt') targetHex = 0x0ea5e9;
      else if (theme === 'amber') targetHex = 0xf59e0b;
      else if (theme === 'crimson') targetHex = 0xef4444;

      _color.setHex(targetHex);
      (glowAccentMat.emissive as THREE.Color).lerp(_color, 0.05);
      (radarBeamMat as THREE.MeshBasicMaterial).color.lerp(_color, 0.05);
      rimLight1.color.lerp(_color, 0.05);

      // Threat Attack Vector Simulation Animation
      const threatSim = activeThreatSimRef.current;
      if (threatSim !== 'idle') {
        const tCycle = (elapsed * 1.5) % 2.5;
        const progress = Math.min(1.0, tCycle / 1.6);

        // Calculate attack trajectory from horizon to dome barrier
        const attackAngle = threatSim === 'phish' ? 0.8 : threatSim === 'dnsbl' ? 2.4 : 4.1;
        const startX = Math.cos(attackAngle) * 16;
        const startZ = Math.sin(attackAngle) * 16;
        const startY = 6.5;

        const endX = Math.cos(attackAngle) * 3.6;
        const endZ = Math.sin(attackAngle) * 3.6;
        const endY = 1.8;

        const curX = THREE.MathUtils.lerp(startX, endX, progress);
        const curY = THREE.MathUtils.lerp(startY, endY, progress);
        const curZ = THREE.MathUtils.lerp(startZ, endZ, progress);

        const beam = threatBeams[0];
        const positions = (beam.geometry.attributes.position as THREE.BufferAttribute);
        positions.setXYZ(0, startX, startY, startZ);
        positions.setXYZ(1, curX, curY, curZ);
        positions.needsUpdate = true;
        (beam.material as THREE.LineBasicMaterial).opacity = 0.95;

        // Spark explosion on shield impact
        if (progress >= 0.95) {
          sparkMesh.visible = true;
          sparkMesh.position.set(endX, endY, endZ);
          const sScale = 1.0 + Math.sin(elapsed * 20) * 0.4;
          sparkMesh.scale.set(sScale, sScale, sScale);
        } else {
          sparkMesh.visible = false;
        }
      } else {
        threatBeams.forEach((b) => ((b.material as THREE.LineBasicMaterial).opacity = 0));
        sparkMesh.visible = false;
      }

      renderer.render(scene, camera);
      frameId = requestAnimationFrame(animate);
    }

    frameId = requestAnimationFrame(animate);

    // Handle Window Resize
    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth || window.innerWidth;
      const h = container.clientHeight || 560;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    // Cleanup & Resource Management (Disposes geometry, textures, materials)
    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener('resize', handleResize);

      groundGeo.dispose();
      groundMat.dispose();
      gridTexture.dispose();
      shadowGeo.dispose();
      shadowMat.dispose();
      contactTexture.dispose();

      baseGeo.dispose();
      subBaseGeo.dispose();
      wellGeo.dispose();
      crystalGeo.dispose();
      pillarGeo.dispose();
      ring1Geo.dispose();
      ring2Geo.dispose();
      domeGeo.dispose();
      pylonBevelGeo.dispose();
      pylonStemGeo.dispose();
      pylonDishGeo.dispose();
      radarBeamGeo.dispose();
      sparkGeo.dispose();

      primaryMetalMat.dispose();
      conduitDarkMat.dispose();
      glowAccentMat.dispose();
      gimbalRingMat.dispose();
      innerCoreMat.dispose();
      domeMat.dispose();
      domeWireMat.dispose();
      radarBeamMat.dispose();
      sparkMat.dispose();

      threatBeams.forEach((b) => {
        b.geometry.dispose();
        (b.material as THREE.Material).dispose();
      });

      controls.dispose();
      renderer.dispose();
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, []);

  // Compute live threat metrics based on incoming props
  const highRiskThreatCount = useMemo(() => {
    return scans.filter((s) => s.riskScore >= 50).length;
  }, [scans]);

  return (
    <div
      className={`relative w-full overflow-hidden bg-slate-950 font-sans select-none ${
        isFullView ? 'fixed inset-0 z-50 h-screen' : 'h-[620px] rounded-xl border border-slate-800 shadow-2xl'
      }`}
    >
      {/* 1. Dedicated WebGL Mount Ref Container (Outside re-rendering React HUD overlays) */}
      <div ref={containerRef} className="absolute inset-0 w-full h-full cursor-grab active:cursor-grabbing" />

      {/* 2. Top-Left Telemetry HUD Badge */}
      <div className="absolute top-4 left-4 z-20 flex flex-wrap items-center gap-2.5 pointer-events-none">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-700/80 text-white shadow-lg pointer-events-auto">
          <Shield className="w-4 h-4 text-emerald-400" />
          <span className="text-xs font-bold font-display tracking-tight">
            AEGIS 3D THREAT RADAR
          </span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800">
            60 FPS PBR
          </span>
        </div>

        {recentScan && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-700/80 text-white shadow-lg text-xs font-mono pointer-events-auto">
            <span className="text-slate-400">Target:</span>
            <span className="font-bold text-slate-200 truncate max-w-[140px]">
              {recentScan.target}
            </span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                recentScan.riskScore >= 50
                  ? 'bg-red-950 text-red-300 border border-red-800'
                  : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
              }`}
            >
              {recentScan.riskScore}/100
            </span>
          </div>
        )}
      </div>

      {/* 3. Top-Right Window & Sound Controls */}
      <div className="absolute top-4 right-4 z-20 flex items-center gap-2">
        <button
          type="button"
          onClick={() => setSoundEnabled(!soundEnabled)}
          className={`p-2 rounded-lg border text-xs font-medium transition-colors cursor-pointer shadow-lg ${
            soundEnabled
              ? 'bg-emerald-900/80 border-emerald-700 text-emerald-200'
              : 'bg-slate-900/80 border-slate-700 text-slate-400 hover:text-white'
          }`}
          title={soundEnabled ? 'Mute Procedural Audio' : 'Enable Spatial Audio Hum'}
        >
          {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
        </button>

        {onCloseFullView && (
          <button
            type="button"
            onClick={onCloseFullView}
            className="p-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-xs font-medium transition-colors cursor-pointer shadow-lg"
            title={isFullView ? 'Exit Full Screen' : 'Expand Full Screen'}
          >
            {isFullView ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        )}
      </div>

      {/* 4. Unified Collapsible Bottom Control Dock (Zero Viewport Occlusion per Three.js Directive) */}
      <div
        className="absolute z-20 left-1/2 -translate-x-1/2 transition-transform duration-300 ease-out"
        style={{
          bottom: '18px',
          maxWidth: 'min(920px, 94vw)',
          transform: controlsCollapsed
            ? 'translate(-50%, calc(100% - 32px))'
            : 'translate(-50%, 0%)',
        }}
      >
        {/* Dock Collapse / Expand Toggle Button */}
        <div className="flex justify-center -mb-px">
          <button
            type="button"
            onClick={() => setControlsCollapsed(!controlsCollapsed)}
            className="flex items-center gap-1.5 px-3.5 py-1 text-[11px] font-mono font-medium rounded-t-md bg-slate-900 border-t border-x border-slate-700 text-slate-300 hover:text-white cursor-pointer shadow-md transition-colors"
          >
            {controlsCollapsed ? (
              <>
                <ChevronUp className="w-3.5 h-3.5 text-emerald-400" />
                <span>Show Controls (Dock)</span>
              </>
            ) : (
              <>
                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                <span>Hide Controls (Cinema Mode)</span>
              </>
            )}
          </button>
        </div>

        {/* Solid Dock Container (No backdrop-filter per Software-WebGL guidelines) */}
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-700/90 shadow-2xl space-y-3 text-white">
          <div className="flex flex-wrap items-center justify-between gap-4">
            {/* Exploded View Slider */}
            <div className="flex items-center gap-2.5 min-w-[200px] flex-1">
              <Layers className="w-4 h-4 text-emerald-400 shrink-0" />
              <div className="flex-1 space-y-0.5">
                <div className="flex justify-between text-[11px] font-mono text-slate-300">
                  <span>Assembly Separation</span>
                  <span className="text-emerald-400 font-bold">{Math.round(explodedRatio * 100)}%</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.01"
                  value={explodedRatio}
                  onChange={(e) => setExplodedRatio(parseFloat(e.target.value))}
                  className="w-full accent-emerald-500 h-1.5 bg-slate-800 rounded-lg cursor-pointer"
                />
              </div>
            </div>

            {/* Camera View Mode Pills */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-[11px] font-mono">
              <Camera className="w-3.5 h-3.5 text-slate-400 ml-1.5 mr-1" />
              {(
                [
                  { id: 'orbit', label: 'Orbit' },
                  { id: 'radar', label: 'Tactical' },
                  { id: 'core', label: 'Core' },
                  { id: 'patrol', label: 'Patrol' },
                ] as const
              ).map((v) => (
                <button
                  key={v.id}
                  type="button"
                  onClick={() => setActiveCameraView(v.id)}
                  className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                    activeCameraView === v.id
                      ? 'bg-emerald-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {v.label}
                </button>
              ))}
            </div>

            {/* Auto-Orbit Rotation Toggle */}
            <button
              type="button"
              onClick={() => setAutoRotate(!autoRotate)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors cursor-pointer ${
                autoRotate
                  ? 'bg-emerald-950/80 border-emerald-700 text-emerald-300 font-semibold'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <RotateCw className={`w-3.5 h-3.5 ${autoRotate ? 'text-emerald-400' : ''}`} />
              <span>{autoRotate ? 'Auto-Orbit On' : 'Orbit Paused'}</span>
            </button>
          </div>

          {/* Secondary Controls: Threat Simulation & Armor Finish Themes */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-2.5 border-t border-slate-800 text-xs">
            {/* Live Threat Vector Simulation Triggers */}
            <div className="flex items-center gap-1.5 font-mono text-[11px]">
              <Crosshair className="w-3.5 h-3.5 text-red-400" />
              <span className="text-slate-400">Simulate Threat:</span>
              <button
                type="button"
                onClick={() => setActiveThreatSim(activeThreatSim === 'phish' ? 'idle' : 'phish')}
                className={`px-2 py-0.5 rounded border transition-colors cursor-pointer ${
                  activeThreatSim === 'phish'
                    ? 'bg-red-900 border-red-500 text-red-200 font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                Phishing URL Strike
              </button>
              <button
                type="button"
                onClick={() => setActiveThreatSim(activeThreatSim === 'dnsbl' ? 'idle' : 'dnsbl')}
                className={`px-2 py-0.5 rounded border transition-colors cursor-pointer ${
                  activeThreatSim === 'dnsbl'
                    ? 'bg-orange-900 border-orange-500 text-orange-200 font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                DNSBL Attack
              </button>
              <button
                type="button"
                onClick={() => setActiveThreatSim('idle')}
                className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-500 hover:text-slate-300 cursor-pointer"
              >
                Clear
              </button>
            </div>

            {/* Armor Finish Themes */}
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono text-slate-400">Armor Theme:</span>
              {(
                [
                  { id: 'emerald', hex: '#10b981', label: 'Titanium Emerald' },
                  { id: 'cobalt', hex: '#0ea5e9', label: 'Cobalt Shield' },
                  { id: 'amber', hex: '#f59e0b', label: 'Amber Alert' },
                  { id: 'crimson', hex: '#ef4444', label: 'Lockdown Red' },
                ] as const
              ).map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setActiveTheme(t.id)}
                  className={`w-5 h-5 rounded-full border-2 transition-transform cursor-pointer ${
                    activeTheme === t.id ? 'scale-125 border-white' : 'border-transparent opacity-70 hover:opacity-100'
                  }`}
                  style={{ backgroundColor: t.hex }}
                  title={t.label}
                />
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
