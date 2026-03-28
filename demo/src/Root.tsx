import { Composition } from "remotion";
import { DemoVideo } from "./DemoVideo";
import { PwnkitIcon } from "./PwnkitIcon";

export const RemotionRoot = () => {
  return (
    <>
      <Composition
        id="DemoVideo"
        component={DemoVideo}
        durationInFrames={660}
        fps={30}
        width={1280}
        height={720}
      />
      <Composition
        id="PwnkitIcon"
        component={PwnkitIcon}
        durationInFrames={180}
        fps={60}
        width={320}
        height={320}
      />
    </>
  );
};
