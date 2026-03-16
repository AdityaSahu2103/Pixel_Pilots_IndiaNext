'use client';

import { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Sphere, OrbitControls } from '@react-three/drei';
import * as THREE from 'three';

function Globe() {
  const meshRef = useRef();
  const pointsRef = useRef();

  useFrame(({ clock }) => {
    if (meshRef.current) {
      meshRef.current.rotation.y = clock.getElapsedTime() * 0.1;
    }
    if (pointsRef.current) {
      pointsRef.current.rotation.y = clock.getElapsedTime() * 0.08;
    }
  });

  // Generate random attack points on sphere surface
  const attackPoints = useMemo(() => {
    const points = [];
    for (let i = 0; i < 50; i++) {
      const phi = Math.acos(2 * Math.random() - 1);
      const theta = 2 * Math.PI * Math.random();
      const r = 1.52;
      points.push(
        r * Math.sin(phi) * Math.cos(theta),
        r * Math.sin(phi) * Math.sin(theta),
        r * Math.cos(phi)
      );
    }
    return new Float32Array(points);
  }, []);

  return (
    <group>
      {/* Wireframe globe */}
      <Sphere ref={meshRef} args={[1.5, 32, 32]}>
        <meshBasicMaterial
          color="#00F5FF"
          wireframe
          transparent
          opacity={0.08}
        />
      </Sphere>

      {/* Inner glow sphere */}
      <Sphere args={[1.48, 32, 32]}>
        <meshBasicMaterial
          color="#8B5CF6"
          transparent
          opacity={0.03}
        />
      </Sphere>

      {/* Attack points */}
      <points ref={pointsRef}>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            count={attackPoints.length / 3}
            array={attackPoints}
            itemSize={3}
          />
        </bufferGeometry>
        <pointsMaterial
          color="#00F5FF"
          size={0.04}
          transparent
          opacity={0.8}
          sizeAttenuation
        />
      </points>

      {/* Ring */}
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[2, 0.005, 8, 64]} />
        <meshBasicMaterial color="#8B5CF6" transparent opacity={0.3} />
      </mesh>
      <mesh rotation={[Math.PI / 2.5, 0.3, 0]}>
        <torusGeometry args={[2.2, 0.003, 8, 64]} />
        <meshBasicMaterial color="#00F5FF" transparent opacity={0.15} />
      </mesh>
    </group>
  );
}

export default function CyberGlobe({ className = '', height = '400px' }) {
  return (
    <div className={className} style={{ height, width: '100%' }}>
      <Canvas
        camera={{ position: [0, 0, 4.5], fov: 45 }}
        style={{ background: 'transparent' }}
        gl={{ antialias: true, alpha: true }}
      >
        <ambientLight intensity={0.5} />
        <pointLight position={[10, 10, 10]} intensity={0.5} />
        <Globe />
        <OrbitControls
          enableZoom={false}
          enablePan={false}
          autoRotate
          autoRotateSpeed={0.5}
        />
      </Canvas>
    </div>
  );
}
