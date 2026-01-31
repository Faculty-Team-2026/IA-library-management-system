
import libraryVideo from '../../assets/videos/library.mp4';

const VideoBackground = () => {
  return (
    <div className="absolute inset-0 w-full h-full overflow-hidden z-0">
      <video
        autoPlay
        loop
        muted
        playsInline
        className="absolute min-w-full min-h-full object-cover"
      >
        <source src={libraryVideo} type="video/mp4" />
        Your browser does not support the video tag.
      </video>
      {/* Overlay to darken the video slightly */}
      <div className="absolute inset-0 bg-black/30" />
    </div>
  );
};

export default VideoBackground;